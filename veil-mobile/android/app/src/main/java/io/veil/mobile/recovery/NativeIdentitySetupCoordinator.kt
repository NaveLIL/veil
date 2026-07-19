package io.veil.mobile.recovery

import java.lang.ref.WeakReference
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** Process-wide owner for one identity ceremony and its irreversible commit. */
internal object NativeIdentitySetupCoordinator {
  @JvmInline
  value class Lease internal constructor(val id: Long)

  enum class Attachment {
    OWNER,
    COMMITTING,
    COMMITTED,
    FAILED,
    REJECTED,
  }

  enum class CommitOutcome {
    COMMITTED,
    FAILED,
  }

  fun interface Ceremony {
    fun onCoordinatorEvent(event: CoordinatorEvent)
  }

  enum class CoordinatorEvent {
    REVOKED,
    COMMITTED,
    FAILED,
  }

  /** A commit owns every copied secret until [close] overwrites it. */
  internal interface CommitWork : AutoCloseable {
    fun run(): CommitOutcome
  }

  private enum class Phase {
    READY,
    COMMITTING,
    TERMINAL,
  }

  private data class Active(
    val lease: Lease,
    var phase: Phase = Phase.READY,
    var outcome: CommitOutcome? = null,
    var revoked: Boolean = false,
    var clientReleased: Boolean = false,
    var ceremony: WeakReference<Ceremony>? = null,
    var executor: ExecutorService? = null,
  )

  private val lock = Any()
  private var nextId = 1L
  private var active: Active? = null

  fun acquire(): Lease? = synchronized(lock) {
    if (active != null) return@synchronized null
    val lease = Lease(nextId++)
    active = Active(lease)
    lease
  }

  /**
   * Attaches the first protected Activity, an observer for an in-flight
   * commit, or adopts a non-secret lease after full process recreation.
   */
  fun attachOrAdopt(lease: Lease, ceremony: Ceremony): Attachment = synchronized(lock) {
    val current = active
    if (current == null) {
      nextId = maxOf(nextId, lease.id + 1)
      active = Active(lease, ceremony = WeakReference(ceremony))
      return@synchronized Attachment.OWNER
    }
    if (current.lease != lease || current.revoked || current.clientReleased) {
      return@synchronized Attachment.REJECTED
    }

    when (current.phase) {
      Phase.READY -> {
        val attached = current.ceremony?.get()
        if (attached != null && attached !== ceremony) {
          Attachment.REJECTED
        } else {
          current.ceremony = WeakReference(ceremony)
          Attachment.OWNER
        }
      }
      Phase.COMMITTING -> {
        // Activity recreation observes the existing transaction. It must not
        // create a second recovery draft while the worker owns the first one.
        current.ceremony = WeakReference(ceremony)
        Attachment.COMMITTING
      }
      Phase.TERMINAL -> {
        current.ceremony = WeakReference(ceremony)
        when (current.outcome) {
          CommitOutcome.COMMITTED -> Attachment.COMMITTED
          CommitOutcome.FAILED -> Attachment.FAILED
          null -> Attachment.REJECTED
        }
      }
    }
  }

  /**
   * Atomically transfers [work] from the Activity to a process transaction.
   * A `true` result means the coordinator owns [work], including when task
   * scheduling itself fails; a `false` result leaves ownership with caller.
   */
  fun beginCommit(
    lease: Lease,
    ceremony: Ceremony,
    work: CommitWork,
    executor: ExecutorService = newCommitExecutor(),
  ): Boolean {
    val accepted = synchronized(lock) {
      val current = active
      if (
        current?.lease != lease ||
          current.phase != Phase.READY ||
          current.revoked ||
          current.clientReleased ||
          current.ceremony?.get() !== ceremony
      ) {
        false
      } else {
        current.phase = Phase.COMMITTING
        current.executor = executor
        true
      }
    }
    if (!accepted) {
      executor.shutdown()
      return false
    }

    try {
      executor.execute {
        val outcome = try {
          work.run()
        } catch (_: Throwable) {
          CommitOutcome.FAILED
        } finally {
          try {
            work.close()
          } catch (_: Throwable) {
            // Secret cleanup is idempotent and best effort after every path.
          }
        }
        complete(lease, outcome)
        executor.shutdown()
      }
    } catch (_: Throwable) {
      try {
        work.close()
      } catch (_: Throwable) {
        // A rejected task must still overwrite all caller-owned buffers.
      }
      complete(lease, CommitOutcome.FAILED)
      executor.shutdown()
    }
    return true
  }

  /**
   * Detaches exactly [ceremony]; in-flight work remains the sole owner.
   *
   * READY has no transferred commit work, while TERMINAL is published only
   * after the worker has closed every owned secret buffer. Both phases can
   * therefore release the process lease here. This is also the recovery path
   * when Android recreates the process and the original React client (and its
   * pending Promise) no longer exists to call [release].
   */
  fun detach(lease: Lease, ceremony: Ceremony) = synchronized(lock) {
    val current = active ?: return@synchronized
    if (current.lease != lease || current.ceremony?.get() !== ceremony) return@synchronized
    current.ceremony = null
    if (current.phase != Phase.COMMITTING) active = null
  }

  fun revoke(lease: Lease) {
    val ceremony = synchronized(lock) {
      val current = active
      if (current?.lease != lease || current.revoked) return
      current.revoked = true
      current.clientReleased = true
      val observer = current.ceremony?.get()
      if (current.phase == Phase.TERMINAL && observer == null) active = null
      observer
    }
    ceremony?.onCoordinatorEvent(CoordinatorEvent.REVOKED)
  }

  /**
   * Releases the client side. COMMITTING is never cleared until its worker
   * reaches a verified terminal outcome and has closed its secret buffers.
   */
  fun release(lease: Lease) = synchronized(lock) {
    val current = active ?: return@synchronized
    if (current.lease != lease) return@synchronized
    if (current.phase == Phase.COMMITTING) {
      current.clientReleased = true
    } else {
      active = null
    }
  }

  /** Clears only an invalidated READY tombstone; never another live owner. */
  fun discardRejected(lease: Lease) = synchronized(lock) {
    val current = active ?: return@synchronized
    if (
      current.lease == lease &&
        current.phase == Phase.READY &&
        current.revoked &&
        current.clientReleased &&
        current.ceremony?.get() == null
    ) {
      active = null
    }
  }

  private fun complete(lease: Lease, outcome: CommitOutcome) {
    val ceremony = synchronized(lock) {
      val current = active
      if (current?.lease != lease || current.phase != Phase.COMMITTING) {
        return@synchronized null
      }
      current.phase = Phase.TERMINAL
      current.outcome = outcome
      current.executor = null
      val observer = current.ceremony?.get()
      if (current.clientReleased && observer == null) active = null
      observer
    }
    ceremony?.onCoordinatorEvent(
      if (outcome == CommitOutcome.COMMITTED) {
        CoordinatorEvent.COMMITTED
      } else {
        CoordinatorEvent.FAILED
      },
    )
  }

  internal fun resetForTest() {
    val executor = synchronized(lock) {
      val closing = active?.executor
      active = null
      nextId = 1L
      closing
    }
    executor?.shutdown()
  }

  private fun newCommitExecutor(): ExecutorService =
    Executors.newSingleThreadExecutor { operation ->
      Thread(operation, "veil-native-identity-commit").apply { isDaemon = true }
    }
}
