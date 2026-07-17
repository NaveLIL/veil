package io.veil.mobile.recovery

import android.app.Activity
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VeilIdentitySetupResultCorrelationTest {
  @Test
  fun acceptsExactVeilResultsAndSystemGeneratedNullCancellation() {
    assertTrue(correlates(Activity.RESULT_OK, hasData = true, returnedLeaseId = LEASE_ID))
    assertTrue(correlates(Activity.RESULT_CANCELED, hasData = true, returnedLeaseId = LEASE_ID))
    assertTrue(correlates(Activity.RESULT_CANCELED, hasData = false, returnedLeaseId = null))
  }

  @Test
  fun rejectsUncorrelatedOrMalformedResults() {
    assertFalse(correlates(Activity.RESULT_OK, hasData = false, returnedLeaseId = null))
    assertFalse(correlates(Activity.RESULT_OK, hasData = true, returnedLeaseId = LEASE_ID + 1))
    assertFalse(correlates(Activity.RESULT_CANCELED, hasData = true, returnedLeaseId = null))
    assertFalse(correlates(42, hasData = true, returnedLeaseId = LEASE_ID))
    assertFalse(
      VeilIdentitySetupModule.correlatesResult(
        expectedRequestCode = REQUEST_CODE,
        expectedLeaseId = LEASE_ID,
        requestCode = REQUEST_CODE + 1,
        resultCode = Activity.RESULT_CANCELED,
        hasResultData = false,
        returnedLeaseId = null,
      ),
    )
  }

  private fun correlates(resultCode: Int, hasData: Boolean, returnedLeaseId: Long?): Boolean =
    VeilIdentitySetupModule.correlatesResult(
      expectedRequestCode = REQUEST_CODE,
      expectedLeaseId = LEASE_ID,
      requestCode = REQUEST_CODE,
      resultCode = resultCode,
      hasResultData = hasData,
      returnedLeaseId = returnedLeaseId,
    )

  companion object {
    private const val REQUEST_CODE = 0x4000
    private const val LEASE_ID = 73L
  }
}
