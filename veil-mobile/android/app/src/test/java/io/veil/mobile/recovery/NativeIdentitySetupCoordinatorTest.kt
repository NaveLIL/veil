package io.veil.mobile.recovery

import java.util.UUID
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
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
    val first = requireNotNull(acquireTestLease())
    assertNull(acquireTestLease())

    NativeIdentitySetupCoordinator.release(first)

    assertTrue(acquireTestLease() != null)
  }

  @Test
  fun duplicateReadyActivityIsRejectedAndInvalidationCannotBeResurrected() {
    val lease = requireNotNull(acquireTestLease())
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
    val settled = CountDownLatch(1)
    NativeIdentitySetupCoordinator.registerSettlementListener(lease) {
      settled.countDown()
    }

    NativeIdentitySetupCoordinator.revoke(lease)

    assertEquals(NativeIdentitySetupCoordinator.CoordinatorEvent.REVOKED, first.event.get())
    assertFalse(settled.await(100, TimeUnit.MILLISECONDS))
    assertNull(acquireTestLease())
    NativeIdentitySetupCoordinator.detach(lease, first)
    assertTrue(settled.await(5, TimeUnit.SECONDS))
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      NativeIdentitySetupCoordinator.query(lease),
    )
    NativeIdentitySetupCoordinator.discardRejected(lease)
    assertTrue(acquireTestLease() != null)
  }

  @Test
  fun revokedBeforeAttachLeavesOnlyARejectableTombstone() {
    val lease = requireNotNull(acquireTestLease())
    val settled = CountDownLatch(1)
    NativeIdentitySetupCoordinator.registerSettlementListener(lease) {
      settled.countDown()
    }
    NativeIdentitySetupCoordinator.revoke(lease)

    assertTrue(settled.await(5, TimeUnit.SECONDS))
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      NativeIdentitySetupCoordinator.query(lease),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.REJECTED,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, RecordingCeremony()),
    )
    assertNull(acquireTestLease())
    NativeIdentitySetupCoordinator.discardRejected(lease)
    assertTrue(acquireTestLease() != null)
  }

  @Test
  fun recreatedActivityObservesOneCommitAndCannotCreateASecondDraft() {
    val lease = requireNotNull(acquireTestLease())
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
    assertNull(acquireTestLease())

    work.release.countDown()
    assertTrue(observer.delivered.await(5, TimeUnit.SECONDS))
    assertEquals(NativeIdentitySetupCoordinator.CoordinatorEvent.COMMITTED, observer.event.get())
    assertTrue(work.closed.get())
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.COMMITTED,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, RecordingCeremony()),
    )
    NativeIdentitySetupCoordinator.release(lease)
    assertTrue(acquireTestLease() != null)
  }

  @Test
  fun clientReleaseDuringCommitCannotReleaseWorkerOwnership() {
    val lease = requireNotNull(acquireTestLease())
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    val work = BlockingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(lease, owner, work))
    assertTrue(work.started.await(5, TimeUnit.SECONDS))

    NativeIdentitySetupCoordinator.release(lease)
    assertNull(acquireTestLease())
    NativeIdentitySetupCoordinator.detach(lease, owner)
    work.release.countDown()

    assertTrue(work.closedLatch.await(5, TimeUnit.SECONDS))
    assertTrue(work.closed.get())
    assertTrue(awaitLease() != null)
  }

  @Test
  fun executorRejectionStillClosesSecretsAndPublishesFailure() {
    val lease = requireNotNull(acquireTestLease())
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
    val lease = requireNotNull(acquireTestLease())
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    val work = RecordingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(lease, owner, work))
    assertTrue(owner.delivered.await(5, TimeUnit.SECONDS))

    NativeIdentitySetupCoordinator.detach(lease, owner)
    NativeIdentitySetupCoordinator.revoke(lease)
    NativeIdentitySetupCoordinator.discardRejected(lease)

    assertTrue(acquireTestLease() != null)
  }

  @Test
  fun beginCommitIsExactlyOnceAndStaleReleaseCannotClearNewLease() {
    val first = requireNotNull(acquireTestLease())
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

    val second = requireNotNull(acquireTestLease())
    NativeIdentitySetupCoordinator.release(first)
    assertNull(acquireTestLease())
    NativeIdentitySetupCoordinator.release(second)
  }

  @Test
  fun fullProcessRecreationCanAdoptTheNonSecretLease() {
    val lease = requireNotNull(acquireTestLease())
    NativeIdentitySetupCoordinator.resetForTest()

    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.OWNER,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, RecordingCeremony()),
    )
  }

  @Test
  fun processRecreatedTerminalDetachDoesNotRequireTheLostBridgeClient() {
    val lostClientLease = requireNotNull(acquireTestLease())
    NativeIdentitySetupCoordinator.resetForTest()
    val adoptedActivity = RecordingCeremony()
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.OWNER,
      NativeIdentitySetupCoordinator.attachOrAdopt(lostClientLease, adoptedActivity),
    )
    val failedWork = FailedWork()
    assertTrue(
      NativeIdentitySetupCoordinator.beginCommit(
        lostClientLease,
        adoptedActivity,
        failedWork,
      ),
    )
    assertTrue(adoptedActivity.delivered.await(5, TimeUnit.SECONDS))
    assertEquals(
      NativeIdentitySetupCoordinator.CoordinatorEvent.FAILED,
      adoptedActivity.event.get(),
    )
    assertTrue(failedWork.closed.get())
    assertNull(acquireTestLease())

    // The pre-death bridge and its Promise cannot call release(). Detach keeps
    // the exact terminal correlation queryable until a cold bridge consumes it.
    NativeIdentitySetupCoordinator.detach(lostClientLease, adoptedActivity)
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      NativeIdentitySetupCoordinator.queryCorrelation(
        lostClientLease.attemptId,
        lostClientLease.ownerProcessIncarnationId,
      ),
    )
    assertTrue(
      NativeIdentitySetupCoordinator.consumeSettledCorrelation(
        lostClientLease.attemptId,
        lostClientLease.ownerProcessIncarnationId,
      ),
    )

    assertTrue(acquireTestLease() != null)
  }

  @Test
  fun strictIdentityReadRejectsReadyAndCommittingThenReadsAfterTerminal() {
    val reads = AtomicInteger(0)
    val lease = requireNotNull(acquireTestLease())

    assertThrowsUnsettled {
      NativeIdentitySetupCoordinator.withSettledIdentityRead {
        reads.incrementAndGet()
        false
      }
    }
    assertEquals(0, reads.get())

    val owner = RecordingCeremony()
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.OWNER,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner),
    )
    val work = BlockingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(lease, owner, work))
    assertTrue(work.started.await(5, TimeUnit.SECONDS))

    assertThrowsUnsettled {
      NativeIdentitySetupCoordinator.withSettledIdentityRead {
        reads.incrementAndGet()
        false
      }
    }
    assertEquals(0, reads.get())

    work.release.countDown()
    assertTrue(owner.delivered.await(5, TimeUnit.SECONDS))
    assertEquals(NativeIdentitySetupCoordinator.CoordinatorEvent.COMMITTED, owner.event.get())
    assertTrue(
      NativeIdentitySetupCoordinator.withSettledIdentityRead {
        reads.incrementAndGet()
        true
      },
    )
    assertEquals(1, reads.get())
  }

  @Test
  fun acquireCannotLinearizeInsideASettledIdentityRead() {
    val readStarted = CountDownLatch(1)
    val releaseRead = CountDownLatch(1)
    val readFinished = CountDownLatch(1)
    val acquireStarted = CountDownLatch(1)
    val acquireFinished = CountDownLatch(1)
    val acquired = AtomicReference<NativeIdentitySetupCoordinator.Lease?>()

    val reader = thread(start = true, isDaemon = true, name = "settled-identity-read-test") {
      NativeIdentitySetupCoordinator.withSettledIdentityRead {
        readStarted.countDown()
        check(releaseRead.await(5, TimeUnit.SECONDS)) { "identity read was not released" }
        true
      }
      readFinished.countDown()
    }
    assertTrue(readStarted.await(5, TimeUnit.SECONDS))

    val acquirer = thread(start = true, isDaemon = true, name = "identity-acquire-test") {
      acquireStarted.countDown()
      acquired.set(acquireTestLease())
      acquireFinished.countDown()
    }
    assertTrue(acquireStarted.await(5, TimeUnit.SECONDS))
    assertFalse(acquireFinished.await(100, TimeUnit.MILLISECONDS))

    releaseRead.countDown()
    assertTrue(readFinished.await(5, TimeUnit.SECONDS))
    assertTrue(acquireFinished.await(5, TimeUnit.SECONDS))
    reader.join(5_000L)
    acquirer.join(5_000L)
    assertTrue(acquired.get() != null)
  }

  @Test
  fun numericCollisionCannotAliasExactLeaseOrDurableCorrelation() {
    val exact = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE),
    )
    val collision =
      NativeIdentitySetupCoordinator.Lease(exact.id, ATTEMPT_TWO, PROCESS_TWO)
    assertEquals(exact.id, collision.id)
    assertNotEquals(exact, collision)
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      NativeIdentitySetupCoordinator.query(exact),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.CONFLICT,
      NativeIdentitySetupCoordinator.query(collision),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      NativeIdentitySetupCoordinator.queryCorrelation(ATTEMPT_ONE, PROCESS_ONE),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.CONFLICT,
      NativeIdentitySetupCoordinator.queryCorrelation(ATTEMPT_TWO, PROCESS_TWO),
    )

    val owner = RecordingCeremony()
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.OWNER,
      NativeIdentitySetupCoordinator.attachOrAdopt(exact, owner),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.REJECTED,
      NativeIdentitySetupCoordinator.attachOrAdopt(collision, RecordingCeremony()),
    )
    NativeIdentitySetupCoordinator.release(collision)
    NativeIdentitySetupCoordinator.abandonClient(collision)
    NativeIdentitySetupCoordinator.revoke(collision)
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      NativeIdentitySetupCoordinator.query(exact),
    )
    assertNull(owner.event.get())
  }

  @Test
  fun staleTupleCompletionAndReleaseCannotMutateNumericIdReplacement() {
    val stale = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE),
    )
    val staleOwner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(stale, staleOwner)
    val staleWork = BlockingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(stale, staleOwner, staleWork))
    assertTrue(staleWork.started.await(5, TimeUnit.SECONDS))

    NativeIdentitySetupCoordinator.resetForTest()
    val replacement = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_TWO, PROCESS_TWO),
    )
    assertEquals(stale.id, replacement.id)
    assertNotEquals(stale, replacement)
    NativeIdentitySetupCoordinator.release(stale)
    NativeIdentitySetupCoordinator.abandonClient(stale)

    staleWork.release.countDown()
    assertTrue(staleWork.closedLatch.await(5, TimeUnit.SECONDS))
    assertFalse(staleOwner.delivered.await(100, TimeUnit.MILLISECONDS))
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      NativeIdentitySetupCoordinator.query(replacement),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.CONFLICT,
      NativeIdentitySetupCoordinator.query(stale),
    )

    NativeIdentitySetupCoordinator.release(replacement)
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.ABSENT,
      NativeIdentitySetupCoordinator.query(replacement),
    )
  }

  @Test
  fun queryStatesAndCorrelationListenerNeedNoNumericLease() {
    val probe = NativeIdentitySetupCoordinator.Lease(77, ATTEMPT_ONE, PROCESS_ONE)
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.ABSENT,
      NativeIdentitySetupCoordinator.query(probe),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.ABSENT,
      NativeIdentitySetupCoordinator.queryCorrelation(ATTEMPT_ONE, PROCESS_ONE),
    )

    val lease = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE),
    )
    assertFalse(
      NativeIdentitySetupCoordinator.consumeSettledCorrelation(ATTEMPT_ONE, PROCESS_ONE),
    )
    assertFalse(
      NativeIdentitySetupCoordinator.consumeSettledCorrelation(ATTEMPT_TWO, PROCESS_TWO),
    )
    val listenerCalled = CountDownLatch(1)
    val listener = NativeIdentitySetupCoordinator.SettlementListener {
      listenerCalled.countDown()
    }
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      NativeIdentitySetupCoordinator.registerSettlementListener(
        ATTEMPT_ONE,
        PROCESS_ONE,
        listener,
      ),
    )
    NativeIdentitySetupCoordinator.removeSettlementListener(
      ATTEMPT_TWO,
      PROCESS_TWO,
      listener,
    )

    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    assertTrue(
      NativeIdentitySetupCoordinator.beginCommit(lease, owner, RecordingWork()),
    )
    assertTrue(listenerCalled.await(5, TimeUnit.SECONDS))
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      NativeIdentitySetupCoordinator.queryCorrelation(ATTEMPT_ONE, PROCESS_ONE),
    )
  }

  @Test
  fun settlementListenerRunsOnlyAfterWorkCloseAndTerminalPublication() {
    val lease = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE),
    )
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    val work = BlockingWork()
    val listenerCalled = CountDownLatch(1)
    val closedAtCallback = AtomicBoolean(false)
    val stateAtCallback =
      AtomicReference<NativeIdentitySetupCoordinator.ReconciliationState?>()
    val listener = NativeIdentitySetupCoordinator.SettlementListener {
      closedAtCallback.set(work.closed.get())
      stateAtCallback.set(NativeIdentitySetupCoordinator.query(lease))
      listenerCalled.countDown()
    }
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      NativeIdentitySetupCoordinator.registerSettlementListener(lease, listener),
    )
    assertEquals(
      0,
      NativeIdentitySetupCoordinator.SettlementListener::class.java
        .getDeclaredMethod("onSettled")
        .parameterCount,
    )
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(lease, owner, work))
    assertTrue(work.started.await(5, TimeUnit.SECONDS))
    assertFalse(listenerCalled.await(100, TimeUnit.MILLISECONDS))

    work.release.countDown()
    assertTrue(listenerCalled.await(5, TimeUnit.SECONDS))
    assertTrue(closedAtCallback.get())
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      stateAtCallback.get(),
    )
    assertTrue(owner.delivered.await(5, TimeUnit.SECONDS))

    val immediateCalls = AtomicInteger(0)
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      NativeIdentitySetupCoordinator.registerSettlementListener(lease) {
        immediateCalls.incrementAndGet()
      },
    )
    assertEquals(1, immediateCalls.get())
  }

  @Test
  fun listenerRemovalUsesExactTupleAndCollisionCannotRemoveListener() {
    val lease = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE),
    )
    val collision =
      NativeIdentitySetupCoordinator.Lease(lease.id, ATTEMPT_TWO, PROCESS_TWO)
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    val retainedCalls = AtomicInteger(0)
    val removedCalls = AtomicInteger(0)
    val correlationRemovedCalls = AtomicInteger(0)
    val retained = NativeIdentitySetupCoordinator.SettlementListener {
      retainedCalls.incrementAndGet()
    }
    val removed = NativeIdentitySetupCoordinator.SettlementListener {
      removedCalls.incrementAndGet()
    }
    val correlationRemoved = NativeIdentitySetupCoordinator.SettlementListener {
      correlationRemovedCalls.incrementAndGet()
    }
    NativeIdentitySetupCoordinator.registerSettlementListener(lease, retained)
    NativeIdentitySetupCoordinator.registerSettlementListener(lease, removed)
    NativeIdentitySetupCoordinator.registerSettlementListener(
      ATTEMPT_ONE,
      PROCESS_ONE,
      correlationRemoved,
    )
    NativeIdentitySetupCoordinator.removeSettlementListener(collision, retained)
    NativeIdentitySetupCoordinator.removeSettlementListener(lease, removed)
    NativeIdentitySetupCoordinator.removeSettlementListener(
      ATTEMPT_ONE,
      PROCESS_ONE,
      correlationRemoved,
    )

    val work = RecordingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(lease, owner, work))
    assertTrue(owner.delivered.await(5, TimeUnit.SECONDS))
    assertEquals(1, retainedCalls.get())
    assertEquals(0, removedCalls.get())
    assertEquals(0, correlationRemovedCalls.get())
  }

  @Test
  fun closeFailureNeverPublishesTerminalOrSettlementWakeup() {
    val lease = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE),
    )
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    val listenerCalls = AtomicInteger(0)
    NativeIdentitySetupCoordinator.registerSettlementListener(lease) {
      listenerCalls.incrementAndGet()
    }
    val work = CloseFailingWork()
    assertTrue(NativeIdentitySetupCoordinator.beginCommit(lease, owner, work))
    assertTrue(work.closeAttempted.await(5, TimeUnit.SECONDS))
    assertFalse(owner.delivered.await(100, TimeUnit.MILLISECONDS))
    assertEquals(0, listenerCalls.get())
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      NativeIdentitySetupCoordinator.query(lease),
    )
    assertThrowsUnsettled {
      NativeIdentitySetupCoordinator.withSettledIdentityRead { true }
    }
  }

  @Test
  fun readyDetachPublishesSettledTombstoneAndWakesListener() {
    val lease = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE),
    )
    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    NativeIdentitySetupCoordinator.abandonClient(lease)
    val listenerCalled = CountDownLatch(1)
    val stateAtCallback =
      AtomicReference<NativeIdentitySetupCoordinator.ReconciliationState?>()
    NativeIdentitySetupCoordinator.registerSettlementListener(
      ATTEMPT_ONE,
      PROCESS_ONE,
    ) {
      stateAtCallback.set(
        NativeIdentitySetupCoordinator.queryCorrelation(ATTEMPT_ONE, PROCESS_ONE),
      )
      listenerCalled.countDown()
    }

    assertNull(owner.event.get())
    NativeIdentitySetupCoordinator.detach(lease, owner)
    assertTrue(listenerCalled.await(5, TimeUnit.SECONDS))
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      stateAtCallback.get(),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.FAILED,
      NativeIdentitySetupCoordinator.attachOrAdopt(lease, RecordingCeremony()),
    )
    assertTrue(
      NativeIdentitySetupCoordinator.consumeSettledCorrelation(ATTEMPT_ONE, PROCESS_ONE),
    )
    assertTrue(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_TWO, PROCESS_TWO) != null,
    )
  }

  @Test
  fun unlaunchedReleaseWakesRegisteredListenerThenFreesSlot() {
    val lease = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE),
    )
    val callbackState =
      AtomicReference<NativeIdentitySetupCoordinator.ReconciliationState?>()
    val called = CountDownLatch(1)
    NativeIdentitySetupCoordinator.registerSettlementListener(
      ATTEMPT_ONE,
      PROCESS_ONE,
    ) {
      callbackState.set(
        NativeIdentitySetupCoordinator.queryCorrelation(ATTEMPT_ONE, PROCESS_ONE),
      )
      called.countDown()
    }

    NativeIdentitySetupCoordinator.release(lease)

    assertTrue(called.await(5, TimeUnit.SECONDS))
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      callbackState.get(),
    )
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.ABSENT,
      NativeIdentitySetupCoordinator.queryCorrelation(ATTEMPT_ONE, PROCESS_ONE),
    )
    assertTrue(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_TWO, PROCESS_TWO) != null,
    )
  }

  @Test
  fun bridgeAbandonDoesNotRevokeReadyOrCommittingActivity() {
    val readyLease = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE),
    )
    val readyOwner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(readyLease, readyOwner)
    NativeIdentitySetupCoordinator.abandonClient(readyLease)
    assertNull(readyOwner.event.get())
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      NativeIdentitySetupCoordinator.query(readyLease),
    )
    NativeIdentitySetupCoordinator.detach(readyLease, readyOwner)
    NativeIdentitySetupCoordinator.release(readyLease)

    val committingLease = requireNotNull(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_TWO, PROCESS_TWO),
    )
    val committingOwner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(committingLease, committingOwner)
    val work = BlockingWork()
    assertTrue(
      NativeIdentitySetupCoordinator.beginCommit(committingLease, committingOwner, work),
    )
    assertTrue(work.started.await(5, TimeUnit.SECONDS))
    NativeIdentitySetupCoordinator.abandonClient(committingLease)
    assertFalse(
      NativeIdentitySetupCoordinator.consumeSettledCorrelation(ATTEMPT_TWO, PROCESS_TWO),
    )
    assertNull(committingOwner.event.get())
    NativeIdentitySetupCoordinator.detach(committingLease, committingOwner)
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      NativeIdentitySetupCoordinator.query(committingLease),
    )

    val recreated = RecordingCeremony()
    assertEquals(
      NativeIdentitySetupCoordinator.Attachment.COMMITTING,
      NativeIdentitySetupCoordinator.attachOrAdopt(committingLease, recreated),
    )
    work.release.countDown()
    assertTrue(recreated.delivered.await(5, TimeUnit.SECONDS))
    assertTrue(work.closed.get())
    assertEquals(
      NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      NativeIdentitySetupCoordinator.query(committingLease),
    )
    assertTrue(
      NativeIdentitySetupCoordinator.consumeSettledCorrelation(ATTEMPT_TWO, PROCESS_TWO),
    )
    assertTrue(
      NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE) != null,
    )
  }

  @Test
  fun reconciliationBarrierBlocksAcquireAndBeginCommitAcrossPolicyExecution() {
    val barrierStarted = CountDownLatch(1)
    val releaseBarrier = CountDownLatch(1)
    val barrierFinished = CountDownLatch(1)
    val acquireStarted = CountDownLatch(1)
    val acquireFinished = CountDownLatch(1)
    val acquired = AtomicReference<NativeIdentitySetupCoordinator.Lease?>()
    val barrier = thread(start = true, isDaemon = true, name = "setup-reconcile-barrier") {
      NativeIdentitySetupCoordinator.withReconciliationBarrier {
        assertEquals(
          NativeIdentitySetupCoordinator.ReconciliationState.ABSENT,
          NativeIdentitySetupCoordinator.queryCorrelation(ATTEMPT_ONE, PROCESS_ONE),
        )
        barrierStarted.countDown()
        check(releaseBarrier.await(5, TimeUnit.SECONDS)) { "barrier was not released" }
      }
      barrierFinished.countDown()
    }
    assertTrue(barrierStarted.await(5, TimeUnit.SECONDS))
    val acquirer = thread(start = true, isDaemon = true, name = "setup-reconcile-acquire") {
      acquireStarted.countDown()
      acquired.set(NativeIdentitySetupCoordinator.acquire(ATTEMPT_ONE, PROCESS_ONE))
      acquireFinished.countDown()
    }
    assertTrue(acquireStarted.await(5, TimeUnit.SECONDS))
    assertFalse(acquireFinished.await(100, TimeUnit.MILLISECONDS))
    releaseBarrier.countDown()
    assertTrue(barrierFinished.await(5, TimeUnit.SECONDS))
    assertTrue(acquireFinished.await(5, TimeUnit.SECONDS))
    barrier.join(5_000L)
    acquirer.join(5_000L)
    val lease = requireNotNull(acquired.get())

    val owner = RecordingCeremony()
    NativeIdentitySetupCoordinator.attachOrAdopt(lease, owner)
    val secondBarrierStarted = CountDownLatch(1)
    val releaseSecondBarrier = CountDownLatch(1)
    val beginStarted = CountDownLatch(1)
    val beginFinished = CountDownLatch(1)
    val work = RecordingWork()
    val secondBarrier = thread(start = true, isDaemon = true) {
      NativeIdentitySetupCoordinator.withReconciliationBarrier {
        secondBarrierStarted.countDown()
        check(releaseSecondBarrier.await(5, TimeUnit.SECONDS)) { "barrier was not released" }
      }
    }
    assertTrue(secondBarrierStarted.await(5, TimeUnit.SECONDS))
    val committer = thread(start = true, isDaemon = true) {
      beginStarted.countDown()
      NativeIdentitySetupCoordinator.beginCommit(lease, owner, work)
      beginFinished.countDown()
    }
    assertTrue(beginStarted.await(5, TimeUnit.SECONDS))
    assertFalse(beginFinished.await(100, TimeUnit.MILLISECONDS))
    releaseSecondBarrier.countDown()
    assertTrue(beginFinished.await(5, TimeUnit.SECONDS))
    assertTrue(owner.delivered.await(5, TimeUnit.SECONDS))
    secondBarrier.join(5_000L)
    committer.join(5_000L)
  }

  private fun assertThrowsUnsettled(operation: () -> Unit) {
    try {
      operation()
      throw AssertionError("expected NativeIdentitySetupUnsettledException")
    } catch (_: NativeIdentitySetupUnsettledException) {
      // Expected: the strict read must remain ambiguous until terminal.
    }
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

  private class FailedWork : RecordingWork() {
    override fun run(): NativeIdentitySetupCoordinator.CommitOutcome =
      NativeIdentitySetupCoordinator.CommitOutcome.FAILED
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

  private class CloseFailingWork : RecordingWork() {
    val closeAttempted = CountDownLatch(1)

    override fun close() {
      closeAttempted.countDown()
      throw IllegalStateException("synthetic close failure")
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
      acquireTestLease()?.let { return it }
      Thread.yield()
    }
    return null
  }

  private fun acquireTestLease(): NativeIdentitySetupCoordinator.Lease? =
    NativeIdentitySetupCoordinator.acquire(nextTestUuid(), nextTestUuid())

  private fun nextTestUuid(): UUID {
    val value = NEXT_TEST_UUID.getAndIncrement()
    return UUID(
      (value shl 16) or 0x4000L,
      Long.MIN_VALUE or value,
    )
  }

  companion object {
    private val NEXT_TEST_UUID = AtomicLong(0x100)
    private val ATTEMPT_ONE = UUID.fromString("a0000000-0000-4000-8000-000000000001")
    private val ATTEMPT_TWO = UUID.fromString("b0000000-0000-4000-8000-000000000002")
    private val PROCESS_ONE = UUID.fromString("10000000-0000-4000-8000-000000000001")
    private val PROCESS_TWO = UUID.fromString("20000000-0000-4000-8000-000000000002")
  }
}
