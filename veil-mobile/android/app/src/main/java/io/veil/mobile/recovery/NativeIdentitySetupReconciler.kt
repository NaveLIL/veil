package io.veil.mobile.recovery

import java.util.UUID

/** Process-coordinator view of the exact journal attempt being reconciled. */
internal enum class NativeIdentitySetupCoordinatorAttemptState {
  IN_PROGRESS,
  SETTLED,
  ABSENT,
  CONFLICT,
}

/** Closed, diagnostic-free result vocabulary for native identity setup. */
internal enum class NativeIdentitySetupReconciliationStatus {
  NONE,
  IN_PROGRESS,
  COMMITTED,
  USER_CANCELLED,
  INTERRUPTED,
  UNCONFIRMED,
}

/** Non-secret durable-record correlation. */
internal data class NativeIdentitySetupReconciliationCorrelation(
  val attemptId: UUID,
  val processIncarnationId: UUID,
  val revision: Int,
) {
  override fun toString(): String = "NativeIdentitySetupReconciliationCorrelation(redacted)"
}

/**
 * A sanitized reconciliation result. It carries only a status and, when a
 * durable record was readable, that record's non-secret correlation and mode.
 */
internal data class NativeIdentitySetupReconciliationResult(
  val status: NativeIdentitySetupReconciliationStatus,
  val correlation: NativeIdentitySetupReconciliationCorrelation?,
  val mode: NativeIdentitySetupJournalMode?,
) {
  init {
    if ((correlation == null) != (mode == null)) {
      throw IllegalArgumentException("setup reconciliation correlation shape is invalid")
    }
    if (status == NativeIdentitySetupReconciliationStatus.NONE && correlation != null) {
      throw IllegalArgumentException("empty setup reconciliation cannot carry correlation")
    }
    if (
      status != NativeIdentitySetupReconciliationStatus.NONE &&
        status != NativeIdentitySetupReconciliationStatus.UNCONFIRMED &&
        correlation == null
    ) {
      throw IllegalArgumentException("setup reconciliation result is missing correlation")
    }
  }

  override fun toString(): String =
    "NativeIdentitySetupReconciliationResult(status=$status, correlation=${correlation != null})"
}

/**
 * Pure reconciliation policy over the non-secret journal and strict vault
 * presence authority.
 *
 * No timer or snapshot fallback participates. A nonterminal record can be
 * converted only when coordinator state proves that no worker can still
 * publish. Terminal receipts are deliberately retained for at-least-once
 * delivery; this policy never clears them.
 *
 * The integration owner must serialize one complete [reconcile] call against
 * coordinator acquire/attach/complete transitions. The injected coordinator
 * callback is a policy input, not a substitute for that outer linearization.
 */
internal class NativeIdentitySetupReconciler(
  private val journal: NativeIdentitySetupJournalAccess,
  private val coordinatorAttemptState:
    (NativeIdentitySetupJournalRecord) -> NativeIdentitySetupCoordinatorAttemptState,
  private val readStrictVaultPresence: () -> Boolean,
) {
  fun reconcile(): NativeIdentitySetupReconciliationResult {
    val record = try {
      journal.readOrNull()
    } catch (_: Throwable) {
      return unconfirmed()
    } ?: return none()

    if (record.phase == NativeIdentitySetupJournalPhase.TERMINAL) {
      return reconcileTerminalRecord(record)
    }

    val coordinatorState = coordinatorStateOrNull(record)
      ?: return unconfirmed(record)
    val currentProcessIncarnationId = try {
      journal.processIncarnationId
    } catch (_: Throwable) {
      return unconfirmed(record)
    }
    val sameProcess = record.processIncarnationId == currentProcessIncarnationId
    if (sameProcess) {
      return reconcileSameProcessNonterminal(
        record,
        coordinatorState,
        currentProcessIncarnationId,
      )
    }
    return reconcileOldProcessNonterminal(
      record,
      coordinatorState,
      currentProcessIncarnationId,
    )
  }

  private fun reconcileSameProcessNonterminal(
    record: NativeIdentitySetupJournalRecord,
    coordinatorState: NativeIdentitySetupCoordinatorAttemptState,
    currentProcessIncarnationId: UUID,
  ): NativeIdentitySetupReconciliationResult {
    if (coordinatorState == NativeIdentitySetupCoordinatorAttemptState.IN_PROGRESS) {
      return result(NativeIdentitySetupReconciliationStatus.IN_PROGRESS, record)
    }

    if (
      record.phase != NativeIdentitySetupJournalPhase.COMMITTING ||
        coordinatorState != NativeIdentitySetupCoordinatorAttemptState.SETTLED
    ) {
      // PREPARED/ACTIVE without an exact live owner, and every absent or
      // conflicting same-process owner, remain ambiguous until process death.
      return unconfirmed(record)
    }

    // SETTLED proves that the exact commit work has closed and cannot publish
    // again. The vault now decides which terminal record may be persisted.
    val present = readVaultOrNull() ?: return unconfirmed(record)
    val outcome =
      if (present) {
        NativeIdentitySetupJournalOutcome.COMMITTED
      } else {
        NativeIdentitySetupJournalOutcome.INTERRUPTED
      }
    val terminal = transitionToTerminalOrNull(record, outcome, currentProcessIncarnationId)
      ?: return unconfirmed(record)
    return result(
      if (present) {
        NativeIdentitySetupReconciliationStatus.COMMITTED
      } else {
        NativeIdentitySetupReconciliationStatus.INTERRUPTED
      },
      terminal,
    )
  }

  private fun reconcileOldProcessNonterminal(
    record: NativeIdentitySetupJournalRecord,
    coordinatorState: NativeIdentitySetupCoordinatorAttemptState,
    currentProcessIncarnationId: UUID,
  ): NativeIdentitySetupReconciliationResult {
    if (coordinatorState != NativeIdentitySetupCoordinatorAttemptState.ABSENT) {
      // Never adopt an old tuple. Any live, settled, or conflicting coordinator
      // state in this process must be resolved by the coordinator owner.
      return unconfirmed(record)
    }

    // The old process is gone and there is no current coordinator. Publish the
    // interrupted tombstone before consulting the vault so an absent read can
    // never race a worker that is still allowed to publish.
    val terminal = transitionToTerminalOrNull(
      record,
      NativeIdentitySetupJournalOutcome.INTERRUPTED,
      currentProcessIncarnationId,
    ) ?: return unconfirmed(record)
    return readTerminalVault(terminal)
  }

  private fun reconcileTerminalRecord(
    record: NativeIdentitySetupJournalRecord,
  ): NativeIdentitySetupReconciliationResult {
    return when (coordinatorStateOrNull(record)) {
      NativeIdentitySetupCoordinatorAttemptState.ABSENT,
      NativeIdentitySetupCoordinatorAttemptState.SETTLED -> readTerminalVault(record)
      NativeIdentitySetupCoordinatorAttemptState.IN_PROGRESS,
      NativeIdentitySetupCoordinatorAttemptState.CONFLICT,
      null -> unconfirmed(record)
    }
  }

  private fun readTerminalVault(
    terminal: NativeIdentitySetupJournalRecord,
  ): NativeIdentitySetupReconciliationResult {
    val present = readVaultOrNull() ?: return unconfirmed(terminal)
    if (present) {
      // The write-once vault remains authoritative even when an Activity or
      // stale journal outcome reported cancellation/interruption.
      return result(NativeIdentitySetupReconciliationStatus.COMMITTED, terminal)
    }
    return when (terminal.outcome) {
      NativeIdentitySetupJournalOutcome.USER_CANCELLED ->
        result(NativeIdentitySetupReconciliationStatus.USER_CANCELLED, terminal)
      NativeIdentitySetupJournalOutcome.INTERRUPTED ->
        result(NativeIdentitySetupReconciliationStatus.INTERRUPTED, terminal)
      NativeIdentitySetupJournalOutcome.COMMITTED,
      null -> unconfirmed(terminal)
    }
  }

  private fun coordinatorStateOrNull(
    record: NativeIdentitySetupJournalRecord,
  ): NativeIdentitySetupCoordinatorAttemptState? =
    try {
      coordinatorAttemptState(record)
    } catch (_: Throwable) {
      null
    }

  private fun readVaultOrNull(): Boolean? =
    try {
      readStrictVaultPresence()
    } catch (_: Throwable) {
      null
    }

  private fun transitionToTerminalOrNull(
    record: NativeIdentitySetupJournalRecord,
    outcome: NativeIdentitySetupJournalOutcome,
    currentProcessIncarnationId: UUID,
  ): NativeIdentitySetupJournalRecord? {
    val terminal = try {
      journal.transition(
        expected = record,
        nextPhase = NativeIdentitySetupJournalPhase.TERMINAL,
        outcome = outcome,
      )
    } catch (_: Throwable) {
      return null
    }
    if (
      terminal.processIncarnationId != currentProcessIncarnationId ||
        terminal.phase != NativeIdentitySetupJournalPhase.TERMINAL ||
        terminal.outcome != outcome ||
        !record.isAllowedSuccessor(terminal)
    ) {
      return null
    }
    return terminal
  }

  private fun none(): NativeIdentitySetupReconciliationResult =
    NativeIdentitySetupReconciliationResult(
      status = NativeIdentitySetupReconciliationStatus.NONE,
      correlation = null,
      mode = null,
    )

  private fun unconfirmed(
    record: NativeIdentitySetupJournalRecord? = null,
  ): NativeIdentitySetupReconciliationResult =
    if (record == null) {
      NativeIdentitySetupReconciliationResult(
        status = NativeIdentitySetupReconciliationStatus.UNCONFIRMED,
        correlation = null,
        mode = null,
      )
    } else {
      result(NativeIdentitySetupReconciliationStatus.UNCONFIRMED, record)
    }

  private fun result(
    status: NativeIdentitySetupReconciliationStatus,
    record: NativeIdentitySetupJournalRecord,
  ): NativeIdentitySetupReconciliationResult =
    NativeIdentitySetupReconciliationResult(
      status = status,
      correlation = NativeIdentitySetupReconciliationCorrelation(
        attemptId = record.attemptId,
        processIncarnationId = record.processIncarnationId,
        revision = record.revision,
      ),
      mode = record.mode,
    )
}
