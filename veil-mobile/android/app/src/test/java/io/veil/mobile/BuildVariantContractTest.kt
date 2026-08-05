package io.veil.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class BuildVariantContractTest {
  @Test
  fun buildIdentityCaptureAndEnrollmentContractIsExact() {
    when (BuildConfig.BUILD_CHANNEL) {
      "debug" -> {
        assertEquals(PRODUCTION_APPLICATION_ID, BuildConfig.APPLICATION_ID)
        assertTrue(BuildConfig.DEBUG)
        assertTrue(BuildConfig.ALLOW_READY_SCREEN_CAPTURE)
        assertProductionEnrollmentContract()
      }

      "release" -> {
        assertEquals(PRODUCTION_APPLICATION_ID, BuildConfig.APPLICATION_ID)
        assertFalse(BuildConfig.DEBUG)
        assertFalse(BuildConfig.ALLOW_READY_SCREEN_CAPTURE)
        assertProductionEnrollmentContract()
      }

      "tester" -> {
        assertEquals(TESTER_APPLICATION_ID, BuildConfig.APPLICATION_ID)
        assertFalse(BuildConfig.DEBUG)
        assertFalse(BuildConfig.ALLOW_READY_SCREEN_CAPTURE)
        assertEquals(TESTER_ENROLLMENT_SCHEME, BuildConfig.ENROLLMENT_SCHEME)
        assertEquals(TESTER_ENROLLMENT_HTTPS_HOST, BuildConfig.ENROLLMENT_HTTPS_HOST)
      }

      else -> fail("Unreviewed Android build channel: ${BuildConfig.BUILD_CHANNEL}")
    }
  }

  private fun assertProductionEnrollmentContract() {
    assertEquals(PRODUCTION_ENROLLMENT_SCHEME, BuildConfig.ENROLLMENT_SCHEME)
    assertEquals(PRODUCTION_ENROLLMENT_HTTPS_HOST, BuildConfig.ENROLLMENT_HTTPS_HOST)
  }

  private companion object {
    const val PRODUCTION_APPLICATION_ID = "io.veil.mobile"
    const val TESTER_APPLICATION_ID = "io.veil.mobile.tester"
    const val PRODUCTION_ENROLLMENT_SCHEME = "veil"
    const val PRODUCTION_ENROLLMENT_HTTPS_HOST = "veil.erez.pro"
    const val TESTER_ENROLLMENT_SCHEME = "veil-tester"
    const val TESTER_ENROLLMENT_HTTPS_HOST = "tester.invalid"
  }
}
