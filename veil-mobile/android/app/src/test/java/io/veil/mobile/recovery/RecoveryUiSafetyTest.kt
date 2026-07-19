package io.veil.mobile.recovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RecoveryUiSafetyTest {
  @Test
  fun scrollIsRetainedOnlyWithinTheSameRecoveryStage() {
    assertEquals(
      417,
      RecoveryUiSafety.retainedScrollY(
        RecoveryStage.RESTORE_ENTRY,
        RecoveryStage.RESTORE_ENTRY,
        417,
      ),
    )
    assertEquals(
      0,
      RecoveryUiSafety.retainedScrollY(
        RecoveryStage.RESTORE_ENTRY,
        RecoveryStage.READY_TO_COMMIT,
        417,
      ),
    )
    assertEquals(
      0,
      RecoveryUiSafety.retainedScrollY(
        RecoveryStage.RESTORE_ENTRY,
        RecoveryStage.RESTORE_ENTRY,
        -1,
      ),
    )
  }

  @Test
  fun suggestionPanelAlwaysReservesTheSameFourCells() {
    assertEquals(4, RecoveryUiSafety.placeholderCount(0, 4))
    assertEquals(3, RecoveryUiSafety.placeholderCount(1, 4))
    assertEquals(0, RecoveryUiSafety.placeholderCount(4, 4))
  }

  @Test
  fun alphabetKeepsFortyEightDpTargetsOnCompactAndLargeFontLayouts() {
    assertEquals(4, RecoveryUiSafety.alphabetColumns(screenWidthDp = 320, fontScale = 1f))
    assertEquals(4, RecoveryUiSafety.alphabetColumns(screenWidthDp = 359, fontScale = 1f))
    assertEquals(5, RecoveryUiSafety.alphabetColumns(screenWidthDp = 360, fontScale = 1f))
    assertEquals(8, RecoveryUiSafety.alphabetColumns(screenWidthDp = 600, fontScale = 1f))
    assertEquals(4, RecoveryUiSafety.alphabetColumns(screenWidthDp = 600, fontScale = 1.5f))
  }

  @Test
  fun nativeActionFailureSkipsRenderAndFailsClosed() {
    var rendered = false
    var failedClosed = false

    RecoveryUiSafety.perform(
      action = { error("synthetic native failure") },
      render = { rendered = true },
      failClosed = { failedClosed = true },
    )

    assertFalse(rendered)
    assertTrue(failedClosed)
  }

  @Test
  fun renderFailureAlsoFailsClosed() {
    var actionCompleted = false
    var failedClosed = false

    RecoveryUiSafety.perform(
      action = { actionCompleted = true },
      render = { error("synthetic render failure") },
      failClosed = { failedClosed = true },
    )

    assertTrue(actionCompleted)
    assertTrue(failedClosed)
  }

  @Test
  fun staleGenerationAndRapidAdvanceCannotReachTheNextChoice() {
    assertTrue(RecoveryUiSafety.isCurrentGeneration(8, 8))
    assertFalse(RecoveryUiSafety.isCurrentGeneration(8, 9))

    val gate = RecoveryAdvanceGate(debounceMs = 400)
    assertTrue(gate.tryAcquire(nowMs = 1_000))
    assertFalse(gate.tryAcquire(nowMs = 1_001))
    assertFalse(gate.tryAcquire(nowMs = 1_399))
    assertTrue(gate.tryAcquire(nowMs = 1_400))
  }

  @Test
  fun staleAndRapidActionsInvokeNoNativeMutationRenderOrFailurePath() {
    val guard = RecoverySetupActionGuard(debounceMs = 400)
    var mutations = 0
    var renders = 0
    var failures = 0

    fun attempt(expected: Long, current: Long, nowMs: Long): Boolean = guard.perform(
      expectedGeneration = expected,
      currentGeneration = current,
      setupEnabled = true,
      advancing = true,
      nowMs = nowMs,
      action = { mutations += 1 },
      render = { renders += 1 },
      failClosed = { failures += 1 },
    )

    assertFalse(attempt(expected = 7, current = 8, nowMs = 900))
    assertTrue(attempt(expected = 8, current = 8, nowMs = 1_000))
    assertFalse(attempt(expected = 8, current = 8, nowMs = 1_001))
    assertEquals(1, mutations)
    assertEquals(1, renders)
    assertEquals(0, failures)
  }

  @Test
  fun failureCallbackCannotEscapeBackIntoTheMainLoop() {
    RecoveryUiSafety.perform(
      action = { error("synthetic native failure") },
      render = { error("must not render") },
      failClosed = { error("synthetic terminal failure") },
    )
  }
}
