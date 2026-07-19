package io.veil.mobile.recovery

import android.app.Activity
import android.content.Intent
import com.facebook.react.bridge.ActivityEventListener
import com.facebook.react.bridge.LifecycleEventListener
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Non-secret React Native launcher for the isolated native ceremony. */
internal class VeilIdentitySetupModule(
  context: ReactApplicationContext,
) : ReactContextBaseJavaModule(context), ActivityEventListener, LifecycleEventListener {
  private data class PendingSetup(
    val id: Long,
    val promise: Promise,
    val lease: NativeIdentitySetupCoordinator.Lease,
    val requestCode: Int,
    var launched: Boolean = false,
  )

  private val lock = Any()
  private val nextId = AtomicLong(1)
  private val hostResumed = AtomicBoolean(false)
  private var pending: PendingSetup? = null
  private var invalidated = false

  init {
    context.addActivityEventListener(this)
    context.addLifecycleEventListener(this)
  }

  override fun getName(): String = "VeilIdentitySetup"

  @ReactMethod
  fun beginNativeIdentitySetup(mode: String, promise: Promise) {
    val parsedMode = RecoveryMode.fromBridge(mode)
    if (parsedMode == null) {
      promise.reject(ERROR_MODE, "Identity setup mode must be create or restore")
      return
    }

    val activity = currentActivity
    if (
      activity == null ||
        activity.isFinishing ||
        activity.isDestroyed ||
        !hostResumed.get() ||
        !activity.hasWindowFocus()
    ) {
      promise.reject(ERROR_ACTIVITY, "Identity setup is unavailable")
      return
    }

    val request = synchronized(lock) {
      if (invalidated) {
        promise.reject(ERROR_ACTIVITY, "Identity setup is unavailable")
        return
      }
      if (pending != null) {
        promise.reject(ERROR_BUSY, "Identity setup is already open")
        return
      }
      val lease = NativeIdentitySetupCoordinator.acquire()
      if (lease == null) {
        promise.reject(ERROR_BUSY, "Identity setup is already open")
        return
      }
      PendingSetup(
        id = nextId.getAndIncrement(),
        promise = promise,
        lease = lease,
        requestCode = allocateRequestCode(),
      ).also { pending = it }
    }

    activity.runOnUiThread {
      var failed: PendingSetup? = null
      synchronized(lock) {
        if (invalidated || pending?.id != request.id) return@synchronized
        if (
          currentActivity !== activity ||
            activity.isFinishing ||
            activity.isDestroyed ||
            !hostResumed.get() ||
            !activity.hasWindowFocus()
        ) {
          failed = pending
          pending = null
          return@synchronized
        }
        try {
          // Serialize the launch against invalidate/result handling. Android
          // cannot synchronously deliver this Activity result.
          activity.startActivityForResult(
            RecoveryActivity.intent(activity, parsedMode, request.lease),
            request.requestCode,
          )
          request.launched = true
        } catch (_: Throwable) {
          failed = pending
          pending = null
        }
      }
      if (failed != null) NativeIdentitySetupCoordinator.release(request.lease)
      failed?.promise?.reject(ERROR_LAUNCH, "Unable to open identity setup")
    }
  }

  override fun onActivityResult(
    activity: Activity,
    requestCode: Int,
    resultCode: Int,
    data: Intent?,
  ) {
    val expected = synchronized(lock) { pending }
    if (expected == null || requestCode != expected.requestCode) return
    val returnedLeaseId = data?.let(RecoveryActivity::resultLeaseId)
    val outcome = classifyResult(
      expectedRequestCode = expected.requestCode,
      expectedLeaseId = expected.lease.id,
      requestCode = requestCode,
      resultCode = resultCode,
      hasResultData = data != null,
      returnedLeaseId = returnedLeaseId,
      returnedOutcome = data?.let(RecoveryActivity::resultOutcome),
    ) ?: return
    val request = takePending(expected.id) ?: return
    NativeIdentitySetupCoordinator.release(request.lease)
    // The result Intent contains only a non-secret outcome and lease correlation id.
    request.promise.resolve(outcome.bridgeValue)
  }

  override fun onNewIntent(intent: Intent) = Unit

  override fun onHostResume() {
    hostResumed.set(true)
  }

  override fun onHostPause() {
    hostResumed.set(false)
  }

  override fun onHostDestroy() {
    hostResumed.set(false)
  }

  override fun invalidate() {
    hostResumed.set(false)
    val request = synchronized(lock) {
      invalidated = true
      pending.also { pending = null }
    }
    request?.let { pendingSetup ->
      if (pendingSetup.launched) {
        NativeIdentitySetupCoordinator.revoke(pendingSetup.lease)
      } else {
        NativeIdentitySetupCoordinator.release(pendingSetup.lease)
      }
    }
    request?.promise?.resolve(NativeIdentitySetupOutcome.INTERRUPTED.bridgeValue)
    reactApplicationContext.removeActivityEventListener(this)
    reactApplicationContext.removeLifecycleEventListener(this)
    super.invalidate()
  }

  private fun takePending(expectedId: Long? = null): PendingSetup? = synchronized(lock) {
    val current = pending ?: return@synchronized null
    if (expectedId != null && current.id != expectedId) return@synchronized null
    pending = null
    current
  }

  companion object {
    private const val REQUEST_CODE_MIN = 0x4000
    private const val REQUEST_CODE_MAX = 0x7ffe
    private val nextRequestCode = AtomicInteger(REQUEST_CODE_MIN)
    private const val ERROR_MODE = "E_VEIL_SETUP_MODE"
    private const val ERROR_ACTIVITY = "E_VEIL_SETUP_ACTIVITY"
    private const val ERROR_BUSY = "E_VEIL_SETUP_BUSY"
    private const val ERROR_LAUNCH = "E_VEIL_SETUP_LAUNCH"

    /**
     * Only an exact, internally consistent success can commit. Once Android
     * returns the expected request code, a missing, mismatched, or contradictory
     * payload is consumed as an interruption so the lease cannot hang or become
     * a false success. Android's synthetic empty RESULT_CANCELED follows the
     * same fail-closed path.
     */
    internal fun classifyResult(
      expectedRequestCode: Int,
      expectedLeaseId: Long,
      requestCode: Int,
      resultCode: Int,
      hasResultData: Boolean,
      returnedLeaseId: Long?,
      returnedOutcome: NativeIdentitySetupOutcome?,
    ): NativeIdentitySetupOutcome? {
      if (requestCode != expectedRequestCode) return null
      if (!hasResultData) return NativeIdentitySetupOutcome.INTERRUPTED
      if (returnedLeaseId != expectedLeaseId) return NativeIdentitySetupOutcome.INTERRUPTED
      return when {
        resultCode == Activity.RESULT_OK &&
          returnedOutcome == NativeIdentitySetupOutcome.COMMITTED ->
          NativeIdentitySetupOutcome.COMMITTED
        resultCode == Activity.RESULT_CANCELED &&
          returnedOutcome == NativeIdentitySetupOutcome.USER_CANCELLED ->
          NativeIdentitySetupOutcome.USER_CANCELLED
        resultCode == Activity.RESULT_CANCELED &&
          returnedOutcome == NativeIdentitySetupOutcome.INTERRUPTED ->
          NativeIdentitySetupOutcome.INTERRUPTED
        else -> NativeIdentitySetupOutcome.INTERRUPTED
      }
    }

    private fun allocateRequestCode(): Int {
      while (true) {
        val current = nextRequestCode.get()
        val following = if (current >= REQUEST_CODE_MAX) REQUEST_CODE_MIN else current + 1
        if (nextRequestCode.compareAndSet(current, following)) return current
      }
    }
  }
}
