package io.veil.mobile.recovery

import android.app.Activity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VeilIdentitySetupResultCorrelationTest {
  @Test
  fun classifiesExactVeilResultsAndSystemGeneratedNullCancellation() {
    assertEquals(
      NativeIdentitySetupOutcome.COMMITTED,
      classify(Activity.RESULT_OK, outcome = NativeIdentitySetupOutcome.COMMITTED),
    )
    assertEquals(
      NativeIdentitySetupOutcome.USER_CANCELLED,
      classify(Activity.RESULT_CANCELED, outcome = NativeIdentitySetupOutcome.USER_CANCELLED),
    )
    assertEquals(
      NativeIdentitySetupOutcome.INTERRUPTED,
      classify(Activity.RESULT_CANCELED, outcome = NativeIdentitySetupOutcome.INTERRUPTED),
    )
    assertEquals(
      NativeIdentitySetupOutcome.INTERRUPTED,
      classify(
        Activity.RESULT_CANCELED,
        hasData = false,
        returnedLeaseId = null,
        outcome = null,
      ),
    )
  }

  @Test
  fun consumesMalformedExpectedResultsAsInterrupted() {
    val malformed = listOf(
      classify(
        Activity.RESULT_OK,
        hasData = false,
        returnedLeaseId = null,
        outcome = null,
      ),
      classify(Activity.RESULT_OK, returnedLeaseId = LEASE_ID + 1),
      classify(Activity.RESULT_CANCELED, returnedLeaseId = null),
      classify(Activity.RESULT_OK, outcome = NativeIdentitySetupOutcome.USER_CANCELLED),
      classify(Activity.RESULT_CANCELED, outcome = NativeIdentitySetupOutcome.COMMITTED),
      classify(Activity.RESULT_CANCELED, outcome = null),
      classify(42, outcome = NativeIdentitySetupOutcome.COMMITTED),
    )

    malformed.forEach { outcome ->
      assertEquals(NativeIdentitySetupOutcome.INTERRUPTED, outcome)
    }
  }

  @Test
  fun ignoresOnlyResultsForAnotherRequestCode() {
    assertNull(
      VeilIdentitySetupModule.classifyResult(
        expectedRequestCode = REQUEST_CODE,
        expectedLeaseId = LEASE_ID,
        requestCode = REQUEST_CODE + 1,
        resultCode = Activity.RESULT_CANCELED,
        hasResultData = false,
        returnedLeaseId = null,
        returnedOutcome = null,
      ),
    )
  }

  private fun classify(
    resultCode: Int,
    hasData: Boolean = true,
    returnedLeaseId: Long? = LEASE_ID,
    outcome: NativeIdentitySetupOutcome? = NativeIdentitySetupOutcome.COMMITTED,
  ): NativeIdentitySetupOutcome? =
    VeilIdentitySetupModule.classifyResult(
      expectedRequestCode = REQUEST_CODE,
      expectedLeaseId = LEASE_ID,
      requestCode = REQUEST_CODE,
      resultCode = resultCode,
      hasResultData = hasData,
      returnedLeaseId = returnedLeaseId,
      returnedOutcome = outcome,
    )

  companion object {
    private const val REQUEST_CODE = 0x4000
    private const val LEASE_ID = 73L
  }
}
