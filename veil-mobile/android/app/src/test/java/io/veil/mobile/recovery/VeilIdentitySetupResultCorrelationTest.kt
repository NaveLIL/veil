package io.veil.mobile.recovery

import android.app.Activity
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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
        returnedAttemptId = null,
        returnedProcessIncarnationId = null,
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
        returnedAttemptId = null,
        returnedProcessIncarnationId = null,
        outcome = null,
      ),
      classify(Activity.RESULT_CANCELED, returnedLeaseId = null),
      classify(Activity.RESULT_CANCELED, returnedLeaseId = 0L),
      classify(Activity.RESULT_CANCELED, returnedLeaseId = -1L),
      classify(Activity.RESULT_CANCELED, returnedAttemptId = null),
      classify(Activity.RESULT_CANCELED, returnedProcessIncarnationId = null),
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
  fun ignoresAnotherRequestCodeAndEveryValidDifferentTuple() {
    assertNull(
      VeilIdentitySetupModule.classifyResult(
        expectedRequestCode = REQUEST_CODE,
        expectedLease = EXPECTED_LEASE,
        requestCode = REQUEST_CODE + 1,
        resultCode = Activity.RESULT_CANCELED,
        hasResultData = false,
        returnedLeaseId = null,
        returnedAttemptId = null,
        returnedProcessIncarnationId = null,
        returnedOutcome = null,
      ),
    )
    assertNull(classify(Activity.RESULT_OK, returnedLeaseId = LEASE_ID + 1))
    assertNull(classify(Activity.RESULT_OK, returnedAttemptId = OTHER_ATTEMPT_ID))
    assertNull(
      classify(
        Activity.RESULT_OK,
        returnedProcessIncarnationId = OTHER_PROCESS_INCARNATION_ID,
      ),
    )
  }

  @Test
  fun parksTransientUnconfirmedButConsumesOnlyDurableTerminalClassifications() {
    assertTrue(
      VeilIdentitySetupModule.shouldAwaitSettlement(
        NativeIdentitySetupReconciliationStatus.UNCONFIRMED,
        hasCorrelation = true,
        coordinatorState = NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      ),
    )
    assertFalse(
      VeilIdentitySetupModule.shouldAwaitSettlement(
        NativeIdentitySetupReconciliationStatus.UNCONFIRMED,
        hasCorrelation = true,
        coordinatorState = NativeIdentitySetupCoordinator.ReconciliationState.SETTLED,
      ),
    )
    assertFalse(
      VeilIdentitySetupModule.shouldAwaitSettlement(
        NativeIdentitySetupReconciliationStatus.UNCONFIRMED,
        hasCorrelation = false,
        coordinatorState = NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS,
      ),
    )

    assertFalse(
      VeilIdentitySetupModule.shouldConsumeCoordinatorTombstone(
        NativeIdentitySetupReconciliationStatus.UNCONFIRMED,
      ),
    )
    assertFalse(
      VeilIdentitySetupModule.shouldConsumeCoordinatorTombstone(
        NativeIdentitySetupReconciliationStatus.IN_PROGRESS,
      ),
    )
    listOf(
      NativeIdentitySetupReconciliationStatus.COMMITTED,
      NativeIdentitySetupReconciliationStatus.USER_CANCELLED,
      NativeIdentitySetupReconciliationStatus.INTERRUPTED,
    ).forEach { status ->
      assertTrue(VeilIdentitySetupModule.shouldConsumeCoordinatorTombstone(status))
    }
  }

  private fun classify(
    resultCode: Int,
    hasData: Boolean = true,
    returnedLeaseId: Long? = LEASE_ID,
    returnedAttemptId: UUID? = ATTEMPT_ID,
    returnedProcessIncarnationId: UUID? = PROCESS_INCARNATION_ID,
    outcome: NativeIdentitySetupOutcome? = NativeIdentitySetupOutcome.COMMITTED,
  ): NativeIdentitySetupOutcome? =
    VeilIdentitySetupModule.classifyResult(
      expectedRequestCode = REQUEST_CODE,
      expectedLease = EXPECTED_LEASE,
      requestCode = REQUEST_CODE,
      resultCode = resultCode,
      hasResultData = hasData,
      returnedLeaseId = returnedLeaseId,
      returnedAttemptId = returnedAttemptId,
      returnedProcessIncarnationId = returnedProcessIncarnationId,
      returnedOutcome = outcome,
    )

  companion object {
    private const val REQUEST_CODE = 0x4000
    private const val LEASE_ID = 73L
    private val ATTEMPT_ID = UUID.fromString("123e4567-e89b-42d3-a456-426614174000")
    private val PROCESS_INCARNATION_ID =
      UUID.fromString("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    private val OTHER_ATTEMPT_ID =
      UUID.fromString("223e4567-e89b-42d3-a456-426614174000")
    private val OTHER_PROCESS_INCARNATION_ID =
      UUID.fromString("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff")
    private val EXPECTED_LEASE = NativeIdentitySetupCoordinator.Lease(
      LEASE_ID,
      ATTEMPT_ID,
      PROCESS_INCARNATION_ID,
    )
  }
}
