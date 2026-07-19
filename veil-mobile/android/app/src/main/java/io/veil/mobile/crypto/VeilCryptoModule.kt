package io.veil.mobile.crypto

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.LifecycleEventListener
import android.view.WindowManager
import io.veil.mobile.BuildConfig
import io.veil.mobile.MainActivity
import uniffi.veil_ffi.VeilIdentity

class VeilCryptoModule(context: ReactApplicationContext) : ReactContextBaseJavaModule(context), LifecycleEventListener {
  private val vault = NativeIdentityVault(context)
  private val identityState = SerializedIdentityState<VeilIdentity>(
    // ReactContext lifecycle state is not a cross-thread authority. Start
    // closed and grant access only from the registered onHostResume callback.
    initiallyAccessible = false,
    loadExisting = {
      if (!vault.hasIdentity()) {
        null
      } else {
        vault.withMnemonicBytes { mnemonicUtf8 ->
          VeilIdentity.fromMnemonicBytes(mnemonicUtf8)
        }
      }
    },
  )

  init {
    context.addLifecycleEventListener(this)
  }

  override fun getName(): String = "VeilCrypto"

  @ReactMethod
  fun hasIdentity(promise: Promise) = resolveScoped(promise) {
    identityState.withExisting { true } ?: false
  }

  @ReactMethod
  fun setSensitiveScreen(enabled: Boolean, promise: Promise) {
    val activity = currentActivity
    if (activity == null) {
      promise.reject("E_VEIL_WINDOW", "current activity is unavailable")
      return
    }
    val trustedReadyActivity = if (activity.javaClass == MainActivity::class.java) {
      activity as MainActivity
    } else {
      null
    }
    val expectedGeneration = trustedReadyActivity?.captureReadyScreenCaptureGeneration()
    activity.runOnUiThread {
      try {
        val isCurrentTrustedReadyActivity = trustedReadyActivity != null &&
          currentActivity === trustedReadyActivity
        val foregroundGenerationCurrent = expectedGeneration != null &&
          trustedReadyActivity?.acceptsReadyScreenCaptureGeneration(expectedGeneration) == true
        if (ReadyScreenCapturePolicy.mayClearProtection(
            protectionRequested = enabled,
            buildAllowsCapture = BuildConfig.ALLOW_READY_SCREEN_CAPTURE,
            isTrustedReadyActivity = isCurrentTrustedReadyActivity,
            foregroundGenerationCurrent = foregroundGenerationCurrent,
          )) {
          // Compile-time debug exception for the already authenticated Ready
          // shell. Release builds cannot reach this downgrade even if renderer
          // code is modified. Only the exact MainActivity class is eligible;
          // RecoveryActivity and dependency Activities stay secure regardless
          // of renderer input. MainActivity re-secures before pause/new intent.
          activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
          activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        promise.resolve(true)
      } catch (_: Throwable) {
        promise.reject("E_VEIL_WINDOW", "Unable to update sensitive screen protection")
      }
    }
  }

  @ReactMethod
  fun getIdentityKey(promise: Promise) = resolveScoped(promise) {
    identityState.withExisting { loaded -> loaded.identityKey().toHex() }
      ?: throw IdentityVaultException("no local identity exists")
  }

  private fun closeIdentity() {
    try {
      identityState.close()
    } catch (_: Throwable) {
      // The serialized owner already dropped its reference before closing.
      // UniFFI's cleaner remains a fallback and lifecycle teardown must not
      // crash or reflect native diagnostics into React Native.
    }
  }

  override fun onHostResume() {
    identityState.resumeAccess()
  }

  override fun onHostPause() {
    try {
      identityState.suspendAccess()
    } catch (_: Throwable) {
      // The owner drops its native reference before close. Backgrounding must
      // remain fail-closed even if native cleanup reports an error.
    }
  }

  override fun onHostDestroy() {
    try {
      identityState.suspendAccess()
    } catch (_: Throwable) {
      // A React context can survive Activity recreation; keep the owner
      // resumable while ensuring no native handle remains usable meanwhile.
    }
  }

  override fun invalidate() {
    reactApplicationContext.removeLifecycleEventListener(this)
    closeIdentity()
    super.invalidate()
  }

  private fun resolveScoped(promise: Promise, operation: () -> Any?) {
    try {
      identityState.runIfAccessible(operation) { result -> promise.resolve(result) }
    } catch (_: IdentityAccessSuspendedException) {
      promise.reject("E_VEIL_LOCKED", "Return to Veil before using the secure identity")
    } catch (_: Throwable) {
      // Native errors and causes may contain storage or cryptographic details.
      // Keep the JS boundary stable and non-diagnostic.
      promise.reject("E_VEIL_CRYPTO", "Native cryptographic operation failed")
    }
  }
}

internal object ReadyScreenCapturePolicy {
  fun mayClearProtection(
    protectionRequested: Boolean,
    buildAllowsCapture: Boolean,
    isTrustedReadyActivity: Boolean,
    foregroundGenerationCurrent: Boolean,
  ): Boolean = !protectionRequested &&
    buildAllowsCapture &&
    isTrustedReadyActivity &&
    foregroundGenerationCurrent
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
