package io.veil.mobile.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Device-local encrypted storage for the recovery phrase used to recreate Rust identity state. */
internal interface NativeIdentityVaultAccess {
  fun hasIdentity(): Boolean

  fun <T> withMnemonicBytes(operation: (ByteArray) -> T): T
}

internal class NativeIdentityVault(context: Context) : NativeIdentityVaultAccess {
  private val preferences =
    context.getSharedPreferences("veil_native_identity_v1", Context.MODE_PRIVATE)

  @Synchronized
  override fun hasIdentity(): Boolean {
    val fields = listOf(KEY_VERSION, KEY_IV, KEY_CIPHERTEXT)
    val present = fields.count(preferences::contains)
    if (present != 0 && present != fields.size) {
      throw IdentityVaultException("identity vault is incomplete")
    }
    return present == fields.size
  }

  @Synchronized
  fun storeNewMnemonic(mnemonic: String) {
    if (hasIdentity()) {
      throw IdentityVaultException("an identity already exists on this device")
    }

    val plaintext = mnemonic.toByteArray(Charsets.UTF_8)
    try {
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
      val ciphertext = cipher.doFinal(plaintext)
      val committed =
        preferences
          .edit()
          .putInt(KEY_VERSION, FORMAT_VERSION)
          .putString(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
          .putString(KEY_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
          .commit()
      ciphertext.fill(0)
      if (!committed) {
        throw IdentityVaultException("identity vault write did not commit")
      }
    } finally {
      plaintext.fill(0)
    }
  }

  /**
   * Opens the recovery phrase only inside the native Android boundary.
   *
   * The supplied byte array is valid only for the duration of [operation] and
   * is cleared before this method returns, including when [operation] throws.
   * Callers must not retain it or return it from the callback.
   */
  @Synchronized
  override fun <T> withMnemonicBytes(operation: (ByteArray) -> T): T {
    if (!hasIdentity()) throw IdentityVaultException("no local identity exists")
    if (preferences.getInt(KEY_VERSION, 0) != FORMAT_VERSION) {
      throw IdentityVaultException("unsupported identity vault version")
    }

    val iv = decode(KEY_IV)
    val ciphertext = decode(KEY_CIPHERTEXT)
    try {
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.DECRYPT_MODE, getExistingKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
      val plaintext = cipher.doFinal(ciphertext)
      return try {
        operation(plaintext)
      } finally {
        plaintext.fill(0)
      }
    } catch (error: Exception) {
      throw IdentityVaultException("identity vault cannot be decrypted", error)
    } finally {
      iv.fill(0)
      ciphertext.fill(0)
    }
  }

  private fun decode(key: String): ByteArray {
    val value = preferences.getString(key, null) ?: throw IdentityVaultException("identity vault is incomplete")
    return try {
      Base64.decode(value, Base64.NO_WRAP)
    } catch (error: IllegalArgumentException) {
      throw IdentityVaultException("identity vault encoding is invalid", error)
    }
  }

  private fun getExistingKey(): SecretKey {
    val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    return (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)
      ?: throw IdentityVaultException("identity vault key is unavailable")
  }

  private fun getOrCreateKey(): SecretKey {
    val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
    generator.init(
      KeyGenParameterSpec.Builder(
          KEY_ALIAS,
          KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setRandomizedEncryptionRequired(true)
        .build(),
    )
    return generator.generateKey()
  }

  companion object {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "veil.mobile.identity.v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val FORMAT_VERSION = 1
    private const val KEY_VERSION = "version"
    private const val KEY_IV = "iv"
    private const val KEY_CIPHERTEXT = "ciphertext"
  }
}

internal class IdentityVaultException(message: String, cause: Throwable? = null) :
  Exception(message, cause)
