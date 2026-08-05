package io.veil.mobile.recovery

import java.lang.ref.WeakReference
import java.util.UUID
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** Strict identity presence is ambiguous while a recovery ceremony can still publish. */
internal class NativeIdentitySetupUnsettledException :
  IllegalStateException("native identity setup has not reached a terminal state")

/** Process-wide owner for one identity ceremony and its irreversible commit. */
internal object NativeIdentitySetupCoordinator {
  /**
   * Non-secret correlation tuple. The numeric id remains an Android result-code
   * convenience only; equality and every mutation include both random UUIDs.
   */
  class Lease internal constructor(
    val id: Long,
    val attemptId: UUID,
    val ownerProcessIncarnationId: UUID,
  ) {
    init {
      require(id > 0) { "identity setup lease id must be positive" }
      requireRandomUuid(attemptId)
      requireRandomUuid(ownerProcessIncarnationId)
      require(attemptId != ownerProcessIncarnationId) {
        "identity setup lease correlation identifiers conflict"
      }
    }

    override fun equals(other: Any?): Boolean =
      other is Lease &&
        id == other.id &&
        attemptId == other.attemptId &&
        ownerProcessIncarnationId == other.ownerProcessIncarnationId

    override fun hashCode(): Int {
      var result = id.hashCode()
      result = 31 * result + attemptId.hashCode()
      return 31 * result + ownerProcessIncarnationId.hashCode()
    }

    internal fun matchesCorrelation(attemptId: UUID, processIncarnationId: UUID): Boolean =
      this.attemptId == attemptId && ownerProcessIncarnationId == processIncarnationId

    override fun toString(): String = "NativeIdentitySetupCoordinator.Lease(redacted)"
  }

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

  /** Exact-tuple view used by durable process-death reconciliation. */
  enum class ReconciliationState {
    IN_PROGRESS,
    SETTLED,
    ABSENT,
    CONFLICT,
  }

  /** Payload-free wakeup; the listener must re-read journal/vault authority. */
  fun interface SettlementListener {
    fun onSettled()
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
    var clientAbandoned: Boolean = false,
    var clientReleaseRequested: Boolean = false,
    var ceremony: WeakReference<Ceremony>? = null,
    var executor: ExecutorService? = null,
    val settlementListeners: MutableList<SettlementListener> = mutableListOf(),
  )

  private val lock = Any()
  private var nextId = 1L
  private var active: Active? = null

  /** Acquires the process slot for one exact durable-journal correlation tuple. */
  fun acquire(attemptId: UUID, ownerProcessIncarnationId: UUID): Lease? = synchronized(lock) {
    if (active != null) return@synchronized null
    val lease = Lease(allocateNumericId(), attemptId, ownerProcessIncarnationId)
    active = Active(lease)
    lease
  }

  fun query(lease: Lease): ReconciliationState = synchronized(lock) {
    queryLocked(lease)
  }

  /** Durable reconciliation is keyed only by the UUID tuple stored in the journal. */
  fun queryCorrelation(
    attemptId: UUID,
    ownerProcessIncarnationId: UUID,
  ): ReconciliationState {
    requireCorrelation(attemptId, ownerProcessIncarnationId)
    return synchronized(lock) {
      queryCorrelationLocked(attemptId, ownerProcessIncarnationId)
    }
  }

  /**
   * Registers one payload-free settlement wakeup without a query/register race.
   * The returned state says whether the listener was retained. For an already
   * SETTLED exact lease the callback is invoked immediately, outside the lock.
   */
  fun registerSettlementListener(
    lease: Lease,
    listener: SettlementListener,
  ): ReconciliationState {
    var notifyImmediately = false
    val state = synchronized(lock) {
      val currentState = queryLocked(lease)
      when (currentState) {
        ReconciliationState.IN_PROGRESS -> {
          val listeners = requireNotNull(active).settlementListeners
          if (listeners.none { it === listener }) listeners += listener
        }
        ReconciliationState.SETTLED -> notifyImmediately = true
        ReconciliationState.ABSENT,
        ReconciliationState.CONFLICT,
        -> Unit
      }
      currentState
    }
    if (notifyImmediately) notifySettlementListener(listener)
    return state
  }

  fun registerSettlementListener(
    attemptId: UUID,
    ownerProcessIncarnationId: UUID,
    listener: SettlementListener,
  ): ReconciliationState {
    requireCorrelation(attemptId, ownerProcessIncarnationId)
    var notifyImmediately = false
    val state = synchronized(lock) {
      val currentState = queryCorrelationLocked(attemptId, ownerProcessIncarnationId)
      when (currentState) {
        ReconciliationState.IN_PROGRESS -> addSettlementListenerLocked(listener)
        ReconciliationState.SETTLED -> notifyImmediately = true
        ReconciliationState.ABSENT,
        ReconciliationState.CONFLICT,
        -> Unit
      }
      currentState
    }
    if (notifyImmediately) notifySettlementListener(listener)
    return state
  }

  fun removeSettlementListener(lease: Lease, listener: SettlementListener) = synchronized(lock) {
    val current = active ?: return@synchronized
    if (current.lease != lease) return@synchronized
    current.settlementListeners.removeAll { it === listener }
  }

  fun removeSettlementListener(
    attemptId: UUID,
    ownerProcessIncarnationId: UUID,
    listener: SettlementListener,
  ) {
    requireCorrelation(attemptId, ownerProcessIncarnationId)
    synchronized(lock) {
      val current = active ?: return@synchronized
      if (!current.lease.matchesCorrelation(attemptId, ownerProcessIncarnationId)) {
        return@synchronized
      }
      current.settlementListeners.removeAll { it === listener }
    }
  }

  /**
   * Lets a cold bridge consume only an exact UUID-correlated terminal slot.
   * READY/COMMITTING are never weakened even when no Activity is attached.
   */
  fun consumeSettledCorrelation(
    attemptId: UUID,
    ownerProcessIncarnationId: UUID,
  ): Boolean {
    requireCorrelation(attemptId, ownerProcessIncarnationId)
    return synchronized(lock) {
      val current = active ?: return@synchronized false
      if (
        !current.lease.matchesCorrelation(attemptId, ownerProcessIncarnationId) ||
          current.phase != Phase.TERMINAL
      ) {
        return@synchronized false
      }
      active = null
      true
    }
  }

  /**
   * Runs one strict durable-identity read only when no ceremony can still
   * publish a record.
   *
   * The coordinator lock deliberately remains held for the complete read. A
   * READY or COMMITTING ceremony is ambiguous and performs no read, while an
   * acquire/beginCommit cannot linearize between the settled-state check and
   * the filesystem result. TERMINAL work has already closed all owned secret
   * buffers before [complete] publishes that phase, so it is safe to read.
   */
  fun <T> withSettledIdentityRead(read: () -> T): T = synchronized(lock) {
    val phase = active?.phase
    if (phase == Phase.READY || phase == Phase.COMMITTING) {
      throw NativeIdentitySetupUnsettledException()
    }
    read()
  }

  /**
   * Linearizes the complete reconcile policy against acquire/attach/commit and
   * settlement. Callers must enter this barrier before taking the journal lock.
   * The monitor is reentrant, so queryCorrelation/withSettledIdentityRead are
   * safe inside [reconcile].
   */
  fun <T> withReconciliationBarrier(reconcile: () -> T): T = synchronized(lock) {
    reconcile()
  }

  /**
   * Attaches the first protected Activity, an observer for an in-flight
   * commit, or adopts a non-secret lease after full process recreation.
   */
  fun attachOrAdopt(lease: Lease, ceremony: Ceremony): Attachment = synchronized(lock) {
    val current = active
    if (current == null) {
      advanceNumericIdPast(lease.id)
      active = Active(lease, ceremony = WeakReference(ceremony))
      return@synchronized Attachment.OWNER
    }
    if (current.lease != lease || current.revoked) {
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
        }
        val closed = closeCommitWork(work)
        if (closed) complete(lease, outcome)
        executor.shutdown()
      }
    } catch (_: Throwable) {
      val closed = closeCommitWork(work)
      if (closed) complete(lease, CommitOutcome.FAILED)
      executor.shutdown()
    }
    return true
  }

  /**
   * Detaches exactly [ceremony]. COMMITTING remains owned by its worker. A
   * READY detach proves no work was transferred, so it publishes a failed
   * terminal tombstone and wakes reconciliation instead of leaving a listener
   * permanently parked. RecoveryActivity closes its draft before this call.
   */
  fun detach(lease: Lease, ceremony: Ceremony) {
    var notification: CompletionNotification? = null
    var clearAfterNotification = false
    synchronized(lock) {
      val current = active ?: return@synchronized
      if (current.lease != lease || current.ceremony?.get() !== ceremony) return@synchronized
      current.ceremony = null
      if (current.phase == Phase.READY) {
        current.phase = Phase.TERMINAL
        current.outcome = CommitOutcome.FAILED
        val listeners = current.settlementListeners.toList()
        current.settlementListeners.clear()
        notification = CompletionNotification(ceremony = null, listeners = listeners)
        clearAfterNotification = current.clientReleaseRequested && !current.clientAbandoned
      }
    }
    val settled = notification ?: return
    settled.listeners.forEach(::notifySettlementListener)
    if (clearAfterNotification) clearReleasedTerminal(lease)
  }

  fun revoke(lease: Lease) {
    var settlementListeners: List<SettlementListener> = emptyList()
    val ceremony = synchronized(lock) {
      val current = active
      if (current?.lease != lease || current.revoked) return
      current.revoked = true
      current.clientAbandoned = true
      val observer = current.ceremony?.get()
      if (current.phase == Phase.READY && observer == null) {
        current.phase = Phase.TERMINAL
        current.outcome = CommitOutcome.FAILED
        settlementListeners = current.settlementListeners.toList()
        current.settlementListeners.clear()
      }
      observer
    }
    settlementListeners.forEach(::notifySettlementListener)
    notifyCeremony(ceremony, CoordinatorEvent.REVOKED)
  }

  /**
   * Releases an unlaunched lease or consumes a terminal lease. A mistakenly
   * late release cannot clear a launched READY or COMMITTING ceremony.
   */
  fun release(lease: Lease) {
    var listeners: List<SettlementListener> = emptyList()
    var clearAfterNotification = false
    synchronized(lock) {
      val current = active ?: return@synchronized
      if (current.lease != lease) return@synchronized
      when (current.phase) {
        Phase.READY -> {
          if (current.ceremony?.get() == null) {
            if (current.settlementListeners.isEmpty()) {
              active = null
            } else {
              current.phase = Phase.TERMINAL
              current.outcome = CommitOutcome.FAILED
              current.clientReleaseRequested = true
              listeners = current.settlementListeners.toList()
              current.settlementListeners.clear()
              clearAfterNotification = true
            }
          } else {
            current.clientReleaseRequested = true
          }
        }
        Phase.COMMITTING -> current.clientReleaseRequested = true
        Phase.TERMINAL -> active = null
      }
    }
    listeners.forEach(::notifySettlementListener)
    if (clearAfterNotification) clearReleasedTerminal(lease)
  }

  /**
   * Detaches a launched React bridge without revoking or clearing the native
   * ceremony. The protected Activity/commit worker remains authoritative.
   */
  fun abandonClient(lease: Lease) = synchronized(lock) {
    val current = active ?: return@synchronized
    if (current.lease != lease) return@synchronized
    current.clientAbandoned = true
  }

  /** Clears only an exact invalidated non-worker tombstone; never a live commit owner. */
  fun discardRejected(lease: Lease) = synchronized(lock) {
    val current = active ?: return@synchronized
    if (
      current.lease == lease &&
        (current.phase == Phase.READY || current.phase == Phase.TERMINAL) &&
        current.revoked &&
        current.clientAbandoned &&
        current.ceremony?.get() == null
    ) {
      active = null
    }
  }

  private fun complete(lease: Lease, outcome: CommitOutcome) {
    val notification = synchronized(lock) {
      val current = active
      if (current?.lease != lease || current.phase != Phase.COMMITTING) {
        return@synchronized null
      }
      current.phase = Phase.TERMINAL
      current.outcome = outcome
      current.executor = null
      val observer = current.ceremony?.get()
      val listeners = current.settlementListeners.toList()
      current.settlementListeners.clear()
      CompletionNotification(
        ceremony = observer,
        listeners = listeners,
        clearAfterNotification =
          current.clientReleaseRequested && current.ceremony?.get() == null &&
            !current.clientAbandoned,
      )
    }
    notification ?: return
    // Wake reconciliation first while the exact terminal lease is still
    // queryable. Every callback is payload-free and isolated from the others.
    notification.listeners.forEach(::notifySettlementListener)
    notifyCeremony(
      notification.ceremony,
      if (outcome == CommitOutcome.COMMITTED) {
        CoordinatorEvent.COMMITTED
      } else {
        CoordinatorEvent.FAILED
      },
    )
    if (notification.clearAfterNotification) clearReleasedTerminal(lease)
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

  private data class CompletionNotification(
    val ceremony: Ceremony?,
    val listeners: List<SettlementListener>,
    val clearAfterNotification: Boolean = false,
  )

  private fun queryLocked(lease: Lease): ReconciliationState {
    val current = active ?: return ReconciliationState.ABSENT
    if (current.lease != lease) return ReconciliationState.CONFLICT
    return if (current.phase == Phase.TERMINAL) {
      ReconciliationState.SETTLED
    } else {
      ReconciliationState.IN_PROGRESS
    }
  }

  private fun queryCorrelationLocked(
    attemptId: UUID,
    ownerProcessIncarnationId: UUID,
  ): ReconciliationState {
    val current = active ?: return ReconciliationState.ABSENT
    if (!current.lease.matchesCorrelation(attemptId, ownerProcessIncarnationId)) {
      return ReconciliationState.CONFLICT
    }
    return if (current.phase == Phase.TERMINAL) {
      ReconciliationState.SETTLED
    } else {
      ReconciliationState.IN_PROGRESS
    }
  }

  private fun addSettlementListenerLocked(listener: SettlementListener) {
    val listeners = requireNotNull(active).settlementListeners
    if (listeners.none { it === listener }) listeners += listener
  }

  private fun clearReleasedTerminal(lease: Lease) = synchronized(lock) {
    val current = active ?: return@synchronized
    if (
      current.lease == lease &&
        current.phase == Phase.TERMINAL &&
        current.clientReleaseRequested &&
        !current.clientAbandoned &&
        current.ceremony?.get() == null
    ) {
      active = null
    }
  }

  private fun closeCommitWork(work: CommitWork): Boolean =
    try {
      work.close()
      true
    } catch (_: Throwable) {
      // Never publish settlement while secret-buffer cleanup is uncertain.
      false
    }

  private fun notifySettlementListener(listener: SettlementListener) {
    try {
      listener.onSettled()
    } catch (_: Throwable) {
      // A wakeup consumer cannot roll back an already-published terminal phase.
    }
  }

  private fun notifyCeremony(ceremony: Ceremony?, event: CoordinatorEvent) {
    try {
      ceremony?.onCoordinatorEvent(event)
    } catch (_: Throwable) {
      // UI observation cannot roll back coordinator ownership or settlement.
    }
  }

  private fun allocateNumericId(): Long {
    val allocated = nextId
    nextId = if (nextId == Long.MAX_VALUE) 1L else nextId + 1L
    return allocated
  }

  private fun advanceNumericIdPast(observed: Long) {
    if (observed >= nextId) {
      nextId = if (observed == Long.MAX_VALUE) 1L else observed + 1L
    }
  }

  private fun newCommitExecutor(): ExecutorService =
    Executors.newSingleThreadExecutor { operation ->
      Thread(operation, "veil-native-identity-commit").apply { isDaemon = true }
    }

  private fun requireRandomUuid(value: UUID) {
    require(value.version() == RANDOM_UUID_VERSION && value.variant() == IETF_UUID_VARIANT) {
      "identity setup lease correlation identifier must be UUIDv4"
    }
  }

  private fun requireCorrelation(attemptId: UUID, ownerProcessIncarnationId: UUID) {
    requireRandomUuid(attemptId)
    requireRandomUuid(ownerProcessIncarnationId)
    require(attemptId != ownerProcessIncarnationId) {
      "identity setup correlation identifiers conflict"
    }
  }

  private const val RANDOM_UUID_VERSION = 4
  private const val IETF_UUID_VARIANT = 2
}
