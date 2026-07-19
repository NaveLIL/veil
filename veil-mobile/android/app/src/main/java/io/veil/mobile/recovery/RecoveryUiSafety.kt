package io.veil.mobile.recovery

/** Non-secret render policy shared by the protected recovery Activity and JVM tests. */
internal object RecoveryUiSafety {
  fun isCurrentGeneration(expected: Long, current: Long): Boolean = expected == current

  fun retainedScrollY(
    previousStage: RecoveryStage?,
    nextStage: RecoveryStage,
    currentScrollY: Int,
  ): Int =
    if (previousStage == nextStage) currentScrollY.coerceAtLeast(0) else 0

  fun placeholderCount(actualSuggestions: Int, reservedSlots: Int): Int {
    require(reservedSlots > 0)
    require(actualSuggestions in 0..reservedSlots)
    return reservedSlots - actualSuggestions
  }

  fun alphabetColumns(screenWidthDp: Int, fontScale: Float): Int {
    require(screenWidthDp > 0)
    require(fontScale > 0f)
    return when {
      fontScale >= 1.5f -> 4
      screenWidthDp >= 600 -> 8
      screenWidthDp < 360 -> 4
      else -> 5
    }
  }

  /** Converts stale/native UI failures into the Activity's generic fail-closed path. */
  fun perform(
    action: () -> Unit,
    render: () -> Unit,
    failClosed: () -> Unit,
  ) {
    try {
      action()
      render()
    } catch (_: Throwable) {
      try {
        failClosed()
      } catch (_: Throwable) {
        // The Activity owns a final no-throw terminal fallback. This helper
        // must never turn a cleanup failure back into a main-loop crash.
      }
    }
  }
}

/** Process-local gate preventing a second tap from selecting the next rendered choice. */
internal class RecoveryAdvanceGate(
  private val debounceMs: Long,
) {
  private var blockedUntilMs = Long.MIN_VALUE

  init {
    require(debounceMs > 0)
  }

  @Synchronized
  fun tryAcquire(nowMs: Long): Boolean {
    if (nowMs < blockedUntilMs) return false
    blockedUntilMs =
      if (nowMs > Long.MAX_VALUE - debounceMs) Long.MAX_VALUE else nowMs + debounceMs
    return true
  }
}

/** Owns generation checks and the one process-local debounce gate for setup actions. */
internal class RecoverySetupActionGuard(
  debounceMs: Long,
) {
  private val advanceGate = RecoveryAdvanceGate(debounceMs)

  fun perform(
    expectedGeneration: Long,
    currentGeneration: Long,
    setupEnabled: Boolean,
    advancing: Boolean,
    nowMs: Long,
    action: () -> Unit,
    render: () -> Unit,
    failClosed: () -> Unit,
  ): Boolean {
    if (!setupEnabled) return false
    if (!RecoveryUiSafety.isCurrentGeneration(expectedGeneration, currentGeneration)) return false
    if (advancing && !advanceGate.tryAcquire(nowMs)) return false
    RecoveryUiSafety.perform(action, render, failClosed)
    return true
  }
}
