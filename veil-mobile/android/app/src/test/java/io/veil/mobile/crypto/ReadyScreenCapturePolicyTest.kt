package io.veil.mobile.crypto

import io.veil.mobile.ReadyScreenCaptureGate
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReadyScreenCapturePolicyTest {
  @Test
  fun `debug ready shell may clear protection only for trusted main activity`() {
    assertTrue(
      ReadyScreenCapturePolicy.mayClearProtection(
        protectionRequested = false,
        buildAllowsCapture = true,
        isTrustedReadyActivity = true,
        foregroundGenerationCurrent = true,
      ),
    )
  }

  @Test
  fun `release build cannot clear protection`() {
    assertFalse(
      ReadyScreenCapturePolicy.mayClearProtection(
        protectionRequested = false,
        buildAllowsCapture = false,
        isTrustedReadyActivity = true,
        foregroundGenerationCurrent = true,
      ),
    )
  }

  @Test
  fun `sensitive state cannot clear protection`() {
    assertFalse(
      ReadyScreenCapturePolicy.mayClearProtection(
        protectionRequested = true,
        buildAllowsCapture = true,
        isTrustedReadyActivity = true,
        foregroundGenerationCurrent = true,
      ),
    )
  }

  @Test
  fun `recovery and dependency activities cannot clear protection`() {
    assertFalse(
      ReadyScreenCapturePolicy.mayClearProtection(
        protectionRequested = false,
        buildAllowsCapture = true,
        isTrustedReadyActivity = false,
        foregroundGenerationCurrent = true,
      ),
    )
  }

  @Test
  fun `paused activity rejects a clear posted by the previous foreground`() {
    val gate = ReadyScreenCaptureGate()
    gate.revoke()
    val foregroundGeneration = gate.grantForeground()

    gate.revoke()

    assertFalse(gate.accepts(foregroundGeneration))
  }

  @Test
  fun `new intent invalidates a stale clear across the following resume`() {
    val gate = ReadyScreenCaptureGate()
    gate.revoke()
    val oldForegroundGeneration = gate.grantForeground()

    gate.revoke()
    gate.grantForeground()

    assertFalse(gate.accepts(oldForegroundGeneration))
  }

  @Test
  fun `create starts ineligible and invalidates any earlier generation`() {
    val gate = ReadyScreenCaptureGate()
    val beforeCreateGeneration = gate.grantForeground()

    gate.revoke()

    assertFalse(gate.accepts(beforeCreateGeneration))
  }

  @Test
  fun `only the fresh resumed generation is eligible`() {
    val gate = ReadyScreenCaptureGate()
    gate.revoke()
    val resumedGeneration = gate.grantForeground()

    assertTrue(gate.accepts(resumedGeneration))
    assertFalse(gate.accepts(resumedGeneration - 1))
  }
}
