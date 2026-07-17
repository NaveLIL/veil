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
  private var identity: VeilIdentity? = null

  init {
    context.addLifecycleEventListener(this)
  }

  override fun getName(): String = "VeilCrypto"

  @ReactMethod
  fun generateMnemonic(promise: Promise) = resolve(promise) { generateMnemonic() }

  @ReactMethod
  fun validateMnemonic(mnemonic: String, promise: Promise) =
    resolve(promise) { validateMnemonic(normalizeMnemonic(mnemonic)) }

  @ReactMethod
  fun hasIdentity(promise: Promise) = resolve(promise) {
    if (!vault.hasIdentity()) false else loadIdentity().let { true }
  }

  @ReactMethod
  fun setSensitiveScreen(enabled: Boolean, promise: Promise) {
    val activity = currentActivity
    if (activity == null) {
      promise.reject("E_VEIL_WINDOW", "current activity is unavailable")
      return
    }
    activity.runOnUiThread {
      try {
        if (enabled) {
          activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
          activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        promise.resolve(true)
      } catch (error: Throwable) {
        promise.reject("E_VEIL_WINDOW", "unable to update sensitive screen protection", error)
      }
    }
  }

  @ReactMethod
  fun createIdentity(mnemonic: String, promise: Promise) = resolve(promise) {
    val normalized = normalizeMnemonic(mnemonic)
    if (!validateMnemonic(normalized)) throw IllegalArgumentException("invalid recovery phrase")
    val candidate = identityFromMnemonic(normalized)
    try {
      val existing = if (vault.hasIdentity()) loadIdentity() else null
      if (existing != null) {
        if (!MessageDigest.isEqual(existing.identityKey(), candidate.identityKey())) {
          throw IdentityVaultException("a different identity already exists on this device")
        }
        return@resolve existing.identityKey().toHex()
      }
      vault.storeNewMnemonic(normalized)
      synchronized(this) {
        identity?.close()
        identity = candidate
      }
      candidate.identityKey().toHex()
    } finally {
      synchronized(this) {
        if (identity !== candidate) candidate.close()
      }
    }
  }

  @ReactMethod
  fun getIdentityKey(promise: Promise) = resolve(promise) { loadIdentity().identityKey().toHex() }

  @Synchronized
  private fun loadIdentity(): VeilIdentity {
    identity?.let { return it }
    val loaded = vault.withMnemonicBytes { mnemonicUtf8 ->
      VeilIdentity.fromMnemonicBytes(mnemonicUtf8)
    }
    identity = loaded
    return loaded
  }

  @Synchronized
  private fun closeIdentity() {
    identity?.close()
    identity = null
  }

  override fun onHostResume() = Unit

  override fun onHostPause() {
    closeIdentity()
  }

  override fun onHostDestroy() {
    closeIdentity()
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

  private inline fun resolve(promise: Promise, operation: () -> Any?) {
    try {
      promise.resolve(operation())
    } catch (error: Throwable) {
      promise.reject("E_VEIL_CRYPTO", error.message ?: "native cryptographic operation failed", error)
    }
  }

  private fun normalizeMnemonic(value: String): String = value.trim().split(Regex("\\s+")).joinToString(" ")
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
