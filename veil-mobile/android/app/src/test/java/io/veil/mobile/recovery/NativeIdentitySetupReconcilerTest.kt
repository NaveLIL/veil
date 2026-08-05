package io.veil.mobile.recovery

import java.io.IOException
import java.lang.reflect.Modifier
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeIdentitySetupReconcilerTest {
  @Test
  fun noJournalReturnsNoneWithoutCoordinatorOrVaultRead() {
    val harness = Harness(record = null)

    val result = harness.reconciler.reconcile()

    assertEquals(NativeIdentitySetupReconciliationStatus.NONE, result.status)
    assertNull(result.correlation)
    assertNull(result.mode)
    assertEquals(listOf("journal.read"), harness.events)
  }

  @Test
  fun exactSameProcessInProgressAttemptBlocksEveryNonterminalPhaseWithoutVaultRead() {
    NONTERMINAL_PHASES.forEach { phase ->
      val record = record(phase, CURRENT_PROCESS)
      val harness = Harness(
        record = record,
        coordinatorState = NativeIdentitySetupCoordinatorAttemptState.IN_PROGRESS,
      )

      val result = harness.reconciler.reconcile()

      assertResult(NativeIdentitySetupReconciliationStatus.IN_PROGRESS, record, result)
      assertEquals(
        "phase $phase crossed the in-progress barrier",
        listOf("journal.read", "coordinator"),
        harness.events,
      )
    }
  }

  @Test
  fun sameProcessPreparedAndActiveWithoutExactLiveCoordinatorStayUnconfirmed() {
    listOf(
      NativeIdentitySetupJournalPhase.PREPARED,
      NativeIdentitySetupJournalPhase.ACTIVE,
    ).forEach { phase ->
      listOf(
        NativeIdentitySetupCoordinatorAttemptState.SETTLED,
        NativeIdentitySetupCoordinatorAttemptState.ABSENT,
        NativeIdentitySetupCoordinatorAttemptState.CONFLICT,
      ).forEach { coordinatorState ->
        val record = record(phase, CURRENT_PROCESS)
        val harness = Harness(record = record, coordinatorState = coordinatorState)

        val result = harness.reconciler.reconcile()

        assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, record, result)
        assertEquals(listOf("journal.read", "coordinator"), harness.events)
      }
    }
  }

  @Test
  fun sameProcessCommittingWithoutExactSettledCoordinatorStaysUnconfirmed() {
    listOf(
      NativeIdentitySetupCoordinatorAttemptState.ABSENT,
      NativeIdentitySetupCoordinatorAttemptState.CONFLICT,
    ).forEach { coordinatorState ->
      val record = record(NativeIdentitySetupJournalPhase.COMMITTING, CURRENT_PROCESS)
      val harness = Harness(record = record, coordinatorState = coordinatorState)

      val result = harness.reconciler.reconcile()

      assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, record, result)
      assertEquals(listOf("journal.read", "coordinator"), harness.events)
    }
  }

  @Test
  fun exactSettledSameProcessCommitReadsVaultThenPublishesCommitted() {
    val committing = record(NativeIdentitySetupJournalPhase.COMMITTING, CURRENT_PROCESS)
    val harness = Harness(
      record = committing,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.SETTLED,
      vaultPresent = true,
    )

    val result = harness.reconciler.reconcile()

    val terminal = requireNotNull(harness.journal.record)
    assertEquals(NativeIdentitySetupJournalPhase.TERMINAL, terminal.phase)
    assertEquals(NativeIdentitySetupJournalOutcome.COMMITTED, terminal.outcome)
    assertResult(NativeIdentitySetupReconciliationStatus.COMMITTED, terminal, result)
    assertEquals(
      listOf("journal.read", "coordinator", "vault", "journal.transition:COMMITTED"),
      harness.events,
    )
  }

  @Test
  fun exactSettledSameProcessCommitReadsVaultThenPublishesInterruptedAbsence() {
    val committing = record(NativeIdentitySetupJournalPhase.COMMITTING, CURRENT_PROCESS)
    val harness = Harness(
      record = committing,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.SETTLED,
      vaultPresent = false,
    )

    val result = harness.reconciler.reconcile()

    val terminal = requireNotNull(harness.journal.record)
    assertEquals(NativeIdentitySetupJournalOutcome.INTERRUPTED, terminal.outcome)
    assertResult(NativeIdentitySetupReconciliationStatus.INTERRUPTED, terminal, result)
    assertEquals(
      listOf("journal.read", "coordinator", "vault", "journal.transition:INTERRUPTED"),
      harness.events,
    )
  }

  @Test
  fun oldProcessNonterminalWithoutCoordinatorPublishesInterruptedBeforeVaultRead() {
    NONTERMINAL_PHASES.forEach { phase ->
      val old = record(phase, OLD_PROCESS)
      val harness = Harness(
        record = old,
        coordinatorState = NativeIdentitySetupCoordinatorAttemptState.ABSENT,
        vaultPresent = false,
      )

      val result = harness.reconciler.reconcile()

      val terminal = requireNotNull(harness.journal.record)
      assertEquals(NativeIdentitySetupJournalPhase.TERMINAL, terminal.phase)
      assertEquals(NativeIdentitySetupJournalOutcome.INTERRUPTED, terminal.outcome)
      assertEquals(CURRENT_PROCESS, terminal.processIncarnationId)
      assertResult(NativeIdentitySetupReconciliationStatus.INTERRUPTED, terminal, result)
      assertEquals(
        "phase $phase read absence before durable interruption",
        listOf("journal.read", "coordinator", "journal.transition:INTERRUPTED", "vault"),
        harness.events,
      )
    }
  }

  @Test
  fun oldProcessInterruptionStillYieldsCommittedWhenVaultIsPresent() {
    val old = record(NativeIdentitySetupJournalPhase.ACTIVE, OLD_PROCESS)
    val harness = Harness(
      record = old,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.ABSENT,
      vaultPresent = true,
    )

    val result = harness.reconciler.reconcile()

    val terminal = requireNotNull(harness.journal.record)
    assertEquals(NativeIdentitySetupJournalOutcome.INTERRUPTED, terminal.outcome)
    assertResult(NativeIdentitySetupReconciliationStatus.COMMITTED, terminal, result)
  }

  @Test
  fun oldProcessTupleIsNeverAdoptedWhenAnyCoordinatorAttemptExists() {
    NONTERMINAL_PHASES.forEach { phase ->
      listOf(
        NativeIdentitySetupCoordinatorAttemptState.IN_PROGRESS,
        NativeIdentitySetupCoordinatorAttemptState.SETTLED,
        NativeIdentitySetupCoordinatorAttemptState.CONFLICT,
      ).forEach { coordinatorState ->
        val record = record(phase, OLD_PROCESS)
        val harness = Harness(record = record, coordinatorState = coordinatorState)

        val result = harness.reconciler.reconcile()

        assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, record, result)
        assertEquals(listOf("journal.read", "coordinator"), harness.events)
        assertEquals(record, harness.journal.record)
      }
    }
  }

  @Test
  fun terminalVaultPresenceOverridesEveryOutcomeAcrossProcessIncarnations() {
    listOf(CURRENT_PROCESS, OLD_PROCESS).forEach { process ->
      listOf(
        NativeIdentitySetupJournalOutcome.COMMITTED,
        NativeIdentitySetupJournalOutcome.USER_CANCELLED,
        NativeIdentitySetupJournalOutcome.INTERRUPTED,
      ).forEach { outcome ->
        listOf(
          NativeIdentitySetupCoordinatorAttemptState.ABSENT,
          NativeIdentitySetupCoordinatorAttemptState.SETTLED,
        ).forEach { coordinatorState ->
          val terminal = terminal(outcome, process)
          val harness = Harness(
            record = terminal,
            coordinatorState = coordinatorState,
            vaultPresent = true,
          )

          val result = harness.reconciler.reconcile()

          assertResult(NativeIdentitySetupReconciliationStatus.COMMITTED, terminal, result)
          assertEquals(listOf("journal.read", "coordinator", "vault"), harness.events)
          assertEquals(0, harness.journal.transitionCount)
        }
      }
    }
  }

  @Test
  fun terminalVaultAbsencePreservesCancellationAndInterruptionButNotCommittedClaim() {
    val expectations = listOf(
      NativeIdentitySetupJournalOutcome.COMMITTED to
        NativeIdentitySetupReconciliationStatus.UNCONFIRMED,
      NativeIdentitySetupJournalOutcome.USER_CANCELLED to
        NativeIdentitySetupReconciliationStatus.USER_CANCELLED,
      NativeIdentitySetupJournalOutcome.INTERRUPTED to
        NativeIdentitySetupReconciliationStatus.INTERRUPTED,
    )
    listOf(CURRENT_PROCESS, OLD_PROCESS).forEach { process ->
      expectations.forEach { (outcome, expectedStatus) ->
        listOf(
          NativeIdentitySetupCoordinatorAttemptState.ABSENT,
          NativeIdentitySetupCoordinatorAttemptState.SETTLED,
        ).forEach { coordinatorState ->
          val terminal = terminal(outcome, process)
          val harness = Harness(
            record = terminal,
            coordinatorState = coordinatorState,
            vaultPresent = false,
          )

          val result = harness.reconciler.reconcile()

          assertResult(expectedStatus, terminal, result)
          assertEquals(listOf("journal.read", "coordinator", "vault"), harness.events)
        }
      }
    }
  }

  @Test
  fun terminalReceiptDoesNotReadVaultBesideInProgressOrConflictingCoordinator() {
    listOf(CURRENT_PROCESS, OLD_PROCESS).forEach { process ->
      listOf(
        NativeIdentitySetupCoordinatorAttemptState.IN_PROGRESS,
        NativeIdentitySetupCoordinatorAttemptState.CONFLICT,
      ).forEach { coordinatorState ->
        val terminal = terminal(NativeIdentitySetupJournalOutcome.INTERRUPTED, process)
        val harness = Harness(record = terminal, coordinatorState = coordinatorState)

        val result = harness.reconciler.reconcile()

        assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, terminal, result)
        assertEquals(listOf("journal.read", "coordinator"), harness.events)
      }
    }
  }

  @Test
  fun journalCorruptionIsUnconfirmedWithoutCorrelationOrAuthorityReads() {
    val harness = Harness(record = null)
    harness.journal.readFailure = IOException("corrupt journal canary")

    val result = harness.reconciler.reconcile()

    assertEquals(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, result.status)
    assertNull(result.correlation)
    assertNull(result.mode)
    assertEquals(listOf("journal.read"), harness.events)
  }

  @Test
  fun processIncarnationReadFailureIsUnconfirmedWithoutVaultRead() {
    val record = record(NativeIdentitySetupJournalPhase.ACTIVE, CURRENT_PROCESS)
    val harness = Harness(
      record = record,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.IN_PROGRESS,
    )
    harness.journal.processIncarnationFailure = IOException("process detail canary")

    val result = harness.reconciler.reconcile()

    assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, record, result)
    assertEquals(listOf("journal.read", "coordinator"), harness.events)
  }

  @Test
  fun coordinatorFailureIsUnconfirmedAndNeverCrossesTheVaultBarrier() {
    listOf(
      record(NativeIdentitySetupJournalPhase.ACTIVE, CURRENT_PROCESS),
      terminal(NativeIdentitySetupJournalOutcome.INTERRUPTED, CURRENT_PROCESS),
    ).forEach { record ->
      val harness = Harness(record = record)
      harness.coordinatorFailure = IOException("coordinator detail canary")

      val result = harness.reconciler.reconcile()

      assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, record, result)
      assertEquals(listOf("journal.read", "coordinator"), harness.events)
    }
  }

  @Test
  fun oldProcessTransitionFailureIsUnconfirmedBeforeVaultRead() {
    val old = record(NativeIdentitySetupJournalPhase.COMMITTING, OLD_PROCESS)
    val harness = Harness(
      record = old,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.ABSENT,
    )
    harness.journal.transitionFailure = IOException("transition detail canary")

    val result = harness.reconciler.reconcile()

    assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, old, result)
    assertEquals(
      listOf("journal.read", "coordinator", "journal.transition:INTERRUPTED"),
      harness.events,
    )
  }

  @Test
  fun sameProcessSettledCommitTransitionFailureCannotPublishVaultResult() {
    val committing = record(NativeIdentitySetupJournalPhase.COMMITTING, CURRENT_PROCESS)
    val harness = Harness(
      record = committing,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.SETTLED,
      vaultPresent = true,
    )
    harness.journal.transitionFailure = IOException("transition detail canary")

    val result = harness.reconciler.reconcile()

    assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, committing, result)
    assertEquals(
      listOf("journal.read", "coordinator", "vault", "journal.transition:COMMITTED"),
      harness.events,
    )
  }

  @Test
  fun malformedTransitionReturnIsRejectedWithoutClaimingTerminalStatus() {
    val old = record(NativeIdentitySetupJournalPhase.PREPARED, OLD_PROCESS)
    val harness = Harness(
      record = old,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.ABSENT,
    )
    harness.journal.returnUnchangedTransition = true

    val result = harness.reconciler.reconcile()

    assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, old, result)
    assertEquals(listOf("journal.read", "coordinator", "journal.transition:INTERRUPTED"), harness.events)
  }

  @Test
  fun vaultFailureIsAlwaysUnconfirmedAndNeverMasqueradesAsAbsence() {
    val terminal = terminal(NativeIdentitySetupJournalOutcome.USER_CANCELLED, CURRENT_PROCESS)
    val harness = Harness(
      record = terminal,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.ABSENT,
    )
    harness.vaultFailure = IOException("vault detail canary")

    val result = harness.reconciler.reconcile()

    assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, terminal, result)
    assertEquals(listOf("journal.read", "coordinator", "vault"), harness.events)
  }

  @Test
  fun sameProcessSettledCommitVaultFailureDoesNotWriteATerminalGuess() {
    val committing = record(NativeIdentitySetupJournalPhase.COMMITTING, CURRENT_PROCESS)
    val harness = Harness(
      record = committing,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.SETTLED,
    )
    harness.vaultFailure = IOException("vault detail canary")

    val result = harness.reconciler.reconcile()

    assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, committing, result)
    assertEquals(listOf("journal.read", "coordinator", "vault"), harness.events)
    assertEquals(0, harness.journal.transitionCount)
    assertEquals(committing, harness.journal.record)
  }

  @Test
  fun terminalReceiptsRepeatAtLeastOnceWithoutBeingClearedOrTransitioned() {
    val terminal = terminal(NativeIdentitySetupJournalOutcome.USER_CANCELLED, OLD_PROCESS)
    val harness = Harness(
      record = terminal,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.ABSENT,
      vaultPresent = false,
    )

    val first = harness.reconciler.reconcile()
    val second = harness.reconciler.reconcile()

    assertEquals(first, second)
    assertResult(NativeIdentitySetupReconciliationStatus.USER_CANCELLED, terminal, first)
    assertEquals(0, harness.journal.transitionCount)
    assertEquals(2, harness.vaultReads)
    assertEquals(terminal, harness.journal.record)
  }

  @Test
  fun failedVaultReadAfterOldProcessTransitionRetriesTheDurableTerminalReceipt() {
    val old = record(NativeIdentitySetupJournalPhase.ACTIVE, OLD_PROCESS)
    val harness = Harness(
      record = old,
      coordinatorState = NativeIdentitySetupCoordinatorAttemptState.ABSENT,
      vaultPresent = false,
    )
    harness.vaultFailure = IOException("first vault read fails")

    val first = harness.reconciler.reconcile()
    val terminal = requireNotNull(harness.journal.record)
    val second = harness.reconciler.reconcile()

    assertResult(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, terminal, first)
    assertResult(NativeIdentitySetupReconciliationStatus.INTERRUPTED, terminal, second)
    assertEquals(1, harness.journal.transitionCount)
    assertEquals(2, harness.vaultReads)
    assertEquals(terminal, harness.journal.record)
  }

  @Test
  fun publicResultShapeContainsOnlyStatusCorrelationAndModeWithoutIdentifiersInText() {
    val terminal = terminal(NativeIdentitySetupJournalOutcome.INTERRUPTED, CURRENT_PROCESS)
    val harness = Harness(record = terminal, vaultPresent = false)

    val result = harness.reconciler.reconcile()

    val resultFields = NativeIdentitySetupReconciliationResult::class.java.declaredFields
      .filterNot { Modifier.isStatic(it.modifiers) }
      .map { it.name }
      .toSet()
    assertEquals(setOf("status", "correlation", "mode"), resultFields)
    val correlationFields = NativeIdentitySetupReconciliationCorrelation::class.java.declaredFields
      .filterNot { Modifier.isStatic(it.modifiers) }
      .map { it.name }
      .toSet()
    assertEquals(setOf("attemptId", "processIncarnationId", "revision"), correlationFields)
    assertFalse(result.toString().contains(ATTEMPT.toString()))
    assertFalse(result.toString().contains(CURRENT_PROCESS.toString()))
    assertFalse(requireNotNull(result.correlation).toString().contains(ATTEMPT.toString()))
  }

  private class Harness(
    record: NativeIdentitySetupJournalRecord?,
    var coordinatorState: NativeIdentitySetupCoordinatorAttemptState =
      NativeIdentitySetupCoordinatorAttemptState.ABSENT,
    var vaultPresent: Boolean = false,
  ) {
    val events = mutableListOf<String>()
    val journal = FakeJournal(CURRENT_PROCESS, record, events)
    var coordinatorFailure: Throwable? = null
    var vaultFailure: Throwable? = null
    var vaultReads = 0

    val reconciler = NativeIdentitySetupReconciler(
      journal = journal,
      coordinatorAttemptState = {
        events += "coordinator"
        coordinatorFailure?.let { failure ->
          coordinatorFailure = null
          throw failure
        }
        coordinatorState
      },
      readStrictVaultPresence = {
        events += "vault"
        vaultReads += 1
        vaultFailure?.let { failure ->
          vaultFailure = null
          throw failure
        }
        vaultPresent
      },
    )
  }

  private class FakeJournal(
    private val stableProcessIncarnationId: UUID,
    var record: NativeIdentitySetupJournalRecord?,
    private val events: MutableList<String>,
  ) : NativeIdentitySetupJournalAccess {
    var readFailure: Throwable? = null
    var processIncarnationFailure: Throwable? = null
    var transitionFailure: Throwable? = null
    var returnUnchangedTransition = false
    var transitionCount = 0

    override val processIncarnationId: UUID
      get() {
        processIncarnationFailure?.let { throw it }
        return stableProcessIncarnationId
      }

    override fun readOrNull(): NativeIdentitySetupJournalRecord? {
      events += "journal.read"
      readFailure?.let { throw it }
      return record
    }

    override fun transition(
      expected: NativeIdentitySetupJournalRecord,
      nextPhase: NativeIdentitySetupJournalPhase,
      outcome: NativeIdentitySetupJournalOutcome?,
    ): NativeIdentitySetupJournalRecord {
      events += "journal.transition:${outcome?.name ?: "NONE"}"
      transitionCount += 1
      transitionFailure?.let { throw it }
      if (returnUnchangedTransition) return expected
      check(record == expected) { "fake journal CAS failed" }
      val next = expected.successor(nextPhase, outcome, processIncarnationId)
      record = next
      return next
    }
  }

  private fun assertResult(
    expectedStatus: NativeIdentitySetupReconciliationStatus,
    expectedRecord: NativeIdentitySetupJournalRecord,
    actual: NativeIdentitySetupReconciliationResult,
  ) {
    assertEquals(expectedStatus, actual.status)
    assertEquals(expectedRecord.mode, actual.mode)
    assertEquals(expectedRecord.attemptId, actual.correlation?.attemptId)
    assertEquals(expectedRecord.processIncarnationId, actual.correlation?.processIncarnationId)
    assertEquals(expectedRecord.revision, actual.correlation?.revision)
  }

  companion object {
    private val CURRENT_PROCESS = UUID.fromString("10000000-0000-4000-8000-000000000001")
    private val OLD_PROCESS = UUID.fromString("20000000-0000-4000-8000-000000000002")
    private val ATTEMPT = UUID.fromString("a0000000-0000-4000-8000-000000000001")
    private val NONTERMINAL_PHASES = listOf(
      NativeIdentitySetupJournalPhase.PREPARED,
      NativeIdentitySetupJournalPhase.ACTIVE,
      NativeIdentitySetupJournalPhase.COMMITTING,
    )

    private fun record(
      phase: NativeIdentitySetupJournalPhase,
      processIncarnationId: UUID,
    ): NativeIdentitySetupJournalRecord {
      val prepared = NativeIdentitySetupJournalRecord.prepared(
        attemptId = ATTEMPT,
        processIncarnationId = processIncarnationId,
        mode = NativeIdentitySetupJournalMode.CREATE,
      )
      return when (phase) {
        NativeIdentitySetupJournalPhase.PREPARED -> prepared
        NativeIdentitySetupJournalPhase.ACTIVE ->
          prepared.successor(
            NativeIdentitySetupJournalPhase.ACTIVE,
            null,
            processIncarnationId,
          )
        NativeIdentitySetupJournalPhase.COMMITTING -> {
          val active = prepared.successor(
            NativeIdentitySetupJournalPhase.ACTIVE,
            null,
            processIncarnationId,
          )
          active.successor(
            NativeIdentitySetupJournalPhase.COMMITTING,
            null,
            processIncarnationId,
          )
        }
        NativeIdentitySetupJournalPhase.TERMINAL ->
          throw IllegalArgumentException("use terminal helper")
      }
    }

    private fun terminal(
      outcome: NativeIdentitySetupJournalOutcome,
      processIncarnationId: UUID,
    ): NativeIdentitySetupJournalRecord {
      val predecessor = when (outcome) {
        NativeIdentitySetupJournalOutcome.COMMITTED ->
          record(NativeIdentitySetupJournalPhase.COMMITTING, processIncarnationId)
        NativeIdentitySetupJournalOutcome.USER_CANCELLED,
        NativeIdentitySetupJournalOutcome.INTERRUPTED ->
          record(NativeIdentitySetupJournalPhase.ACTIVE, processIncarnationId)
      }
      return predecessor.successor(
        NativeIdentitySetupJournalPhase.TERMINAL,
        outcome,
        processIncarnationId,
      )
    }
  }
}
