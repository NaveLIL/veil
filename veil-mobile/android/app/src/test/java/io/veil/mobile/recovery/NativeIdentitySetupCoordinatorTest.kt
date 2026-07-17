package io.veil.mobile.recovery

import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class NativeIdentitySetupCoordinatorTest {
  @Before
  fun resetBefore() = NativeIdentitySetupCoordinator.resetForTest()

  @After
  fun resetAfter() = NativeIdentitySetupCoordinator.resetForTest()

  @Test
  fun onlyOneReactContextCanOwnASetupLease() {
    val first = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    assertNull(NativeIdentitySetupCoordinator.acquire())

    NativeIdentitySetupCoordinator.release(first)

    assertTrue(NativeIdentitySetupCoordinator.acquire() != null)
  }

  @Test
  fun duplicateReadyActivityIsRejectedAndInvalidationCannotBeResurrected() {
    val lease = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    val first = RecordingCeremony()
    val duplicate = RecordingCeremony()
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.OWNER,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, first),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.REJECTED,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, duplicate),
    )

    NativeIdentitySetupCoordinator.revoke(lease)

    assertEquals(NativeIdentitySetupCoordinator.CoordinatorEvent.REVOKED, first.event.get())
    assertNull(NativeIdentitySetupCoordinator.acquire())
    NativeIdentitySetupCoordinator.detach(lease, first)
    assertTrue(NativeIdentitySetupCoordinator.acquire() != null)
  }

  @Test
  fun revokedBeforeAttachLeavesOnlyARejectableTombstone() {
    val lease = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    NativeIdentitySetupCoordinator.revoke(lease)

    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.REJECTED,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, RecordingCeremony()),
    )
    assertNull(NativeIdentitySetupCoordinator.acquire())
    NativeIdentitySetupCoordinator.discardRejected(lease)
    assertTrue(NativeIdentitySetupCoordinator.acquire() != null)
  }

  @Test
  fun recreatedActivityObservesOneCommitAndCannotCreateASecondDraft() {
    val lease = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    val owner = RecordingCeremony()
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.OWNER,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner),
    )
    val work = BlockingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(lease, owner, work))
    assertTrue(work.started.await(5, TimeUnit.SECONDS))

    NativeIdentitySetupCoordinator.detach(lease, owner)
    val observer = RecordingCeremony()
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.COMMITTING,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, observer),
    )
    assertNull(NativeIdentitySetupCoordinator.acquire())

    work.release.countDown()
    assertTrue(observer.delivered.await(5, TimeUnit.SECONDS))
    assertEquals(NativeIdentitySetupCoordinator.CoordinatorEvent.COMMITTED, observer.event.get())
    assertTrue(work.closed.get())
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.COMMITTED,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, RecordingCeremony()),
    )
    NativeIdentitySetupCoordinator.release(lease)
    assertTrue(NativeIdentitySetupCoordinator.acquire() != null)
  }

  @Test
  fun clientReleaseDuringCommitCannotReleaseWorkerOwnership() {
    val lease = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    val work = BlockingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(lease, owner, work))
    assertTrue(work.started.await(5, TimeUnit.SECONDS))

    NativeIdentitySetupCoordinator.release(lease)
    assertNull(NativeIdentitySetupCoordinator.acquire())
    NativeIdentitySetupCoordinator.detach(lease, owner)
    work.release.countDown()

    assertTrue(work.closedLatch.await(5, TimeUnit.SECONDS))
    assertTrue(work.closed.get())
    assertTrue(awaitLease() != null)
  }

  @Test
  fun executorRejectionStillClosesSecretsAndPublishesFailure() {
    val lease = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    val work = RecordingWork()

    assertTrue(
      NativeIdentitySetupCoordinator.beginCommit(lease, owner, work, RejectingExecutor()),
    )

    assertTrue(work.closed.get())
    assertEquals(NativeIdentitySetupCoordinator.CoordinatorEvent.FAILED, owner.event.get())
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.FAILED,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, RecordingCeremony()),
    )
  }

  @Test
  fun terminalDetachThenClientRevokeCannotLeavePermanentBusyState() {
    val lease = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    val work = RecordingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(lease, owner, work))
    assertTrue(owner.delivered.await(5, TimeUnit.SECONDS))

    NativeIdentitySetupCoordinator.detach(lease, owner)
    NativeIdentitySetupCoordinator.revoke(lease)

    assertTrue(NativeIdentitySetupCoordinator.acquire() != null)
  }

  @Test
  fun beginCommitIsExactlyOnceAndStaleReleaseCannotClearNewLease() {
    val first = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(first, owner)
    val work = BlockingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(first, owner, work))
    assertTrue(work.started.await(5, TimeUnit.SECONDS))

    val rejected = RecordingWork()
    assertFalse(NativeIdentitySetupCoordinator.beginCommit(first, owner, rejected))
    rejected.close()
    assertTrue(rejected.closed.get())
    work.release.countDown()
    assertTrue(owner.delivered.await(5, TimeUnit.SECONDS))
    NativeIdentitySetupCoordinator.release(first)

    val second = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    NativeIdentitySetupCoordinator.release(first)
    assertNull(NativeIdentitySetupCoordinator.acquire())
    NativeIdentitySetupCoordinator.release(second)
  }

  @Test
  fun fullProcessRecreationCanAdoptTheNonSecretLease() {
    val lease = requireNotNull(NativeIdentitySetupCoordinator.acquire())
    NativeIdentitySetupCoordinator.resetForTest()

    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.OWNER,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, RecordingCeremony()),
    )
  }

  private class RecordingCeremony : NativeIdentitySetupCoordinator.Ceremony {
    val event = AtomicReference<NativeIdentitySetupCoordinator.CoordinatorEvent?>()
    val delivered = CountDownLatch(1)

    override fun onCoordinatorEvent(event: NativeIdentitySetupCoordinator.CoordinatorEvent) {
      this.event.set(event)
      delivered.countDown()
    }
  }

  private open class RecordingWork : NativeIdentitySetupCoordinator.CommitWork {
    val closed = AtomicBoolean(false)
    override fun run(): NativeIdentitySetupCoordinator.CommitOutcome =
      NativeIdentitySetupCoordinator.CommitOutcome.COMMITTED

    override fun close() {
      closed.set(true)
    }
  }

  private class BlockingWork : RecordingWork() {
    val started = CountDownLatch(1)
    val release = CountDownLatch(1)
    val closedLatch = CountDownLatch(1)

    override fun run(): NativeIdentitySetupCoordinator.CommitOutcome {
      started.countDown()
      check(release.await(5, TimeUnit.SECONDS)) { "commit barrier timed out" }
      return NativeIdentitySetupCoordinator.CommitOutcome.COMMITTED
    }

    override fun close() {
      super.close()
      closedLatch.countDown()
    }
  }

  private class RejectingExecutor : AbstractExecutorService() {
    private var shutdown = false
    override fun shutdown() { shutdown = true }
    override fun shutdownNow(): MutableList<Runnable> { shutdown = true; return mutableListOf() }
    override fun isShutdown(): Boolean = shutdown
    override fun isTerminated(): Boolean = shutdown
    override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean = shutdown
    override fun execute(command: Runnable) = throw RejectedExecutionException("test rejection")
  }

  private fun awaitLease(): NativeIdentitySetupCoordinator.Lease? {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
    while (System.nanoTime() < deadline) {
      NativeIdentitySetupCoordinator.acquire()?.let { return it }
      Thread.yield()
    }
    return null
  }
}
