package io.veil.mobile.crypto

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.LifecycleEventListener
import java.security.MessageDigest
import android.view.WindowManager
import uniffi.veil_ffi.VeilIdentity
import uniffi.veil_ffi.generateMnemonic
import uniffi.veil_ffi.validateMnemonic

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
  fun generateMnemonic(promise: Promise) = resolveScoped(promise) { generateMnemonic() }

  @ReactMethod
  fun validateMnemonic(mnemonic: String, promise: Promise) =
    resolveScoped(promise) { validateMnemonic(normalizeMnemonic(mnemonic)) }

  @ReactMethod
  fun hasIdentity(promise: Promise) = resolveScoped(promise) {
    identityState.withExisting { true } ?: false
  }

  @ReactMethod
  fun setSensitiveScreen(_enabled: Boolean, promise: Promise) {
    val activity = currentActivity
    if (activity == null) {
      promise.reject("E_VEIL_WINDOW", "current activity is unavailable")
      return
    }
    activity.runOnUiThread {
      try {
        // FLAG_SECURE is Activity-wide for the closed preview. The legacy
        // recovery UI may request stronger protection, but its cleanup must
        // never downgrade the global task/screenshot boundary.
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        promise.resolve(true)
      } catch (_: Throwable) {
        promise.reject("E_VEIL_WINDOW", "Unable to update sensitive screen protection")
      }
    }
  }

  @ReactMethod
  fun createIdentity(mnemonic: String, promise: Promise) = resolveScoped(promise) {
    val normalized = normalizeMnemonic(mnemonic)
    if (!validateMnemonic(normalized)) throw IllegalArgumentException("invalid recovery phrase")
    val candidate = identityFromMnemonic(normalized)
    var installed = false
    try {
      val candidateKey = candidate.identityKey()
      installed = identityState.installOrVerify(
        candidate = candidate,
        verifyExisting = { existing, _ ->
          if (!MessageDigest.isEqual(existing.identityKey(), candidateKey)) {
            throw IdentityVaultException("a different identity already exists on this device")
          }
        },
        persistCandidate = { vault.storeNewMnemonic(normalized) },
      )
      candidateKey.toHex()
    } finally {
      if (!installed) {
        candidate.close()
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

  private fun identityFromMnemonic(mnemonic: String): VeilIdentity {
    val mnemonicUtf8 = mnemonic.toByteArray(Charsets.UTF_8)
    return try {
      VeilIdentity.fromMnemonicBytes(mnemonicUtf8)
    } finally {
      mnemonicUtf8.fill(0)
    }
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

  private fun normalizeMnemonic(value: String): String = value.trim().split(Regex("\\s+")).joinToString(" ")
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
