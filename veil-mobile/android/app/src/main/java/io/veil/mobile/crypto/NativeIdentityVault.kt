package io.veil.mobile.crypto

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
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
  private val repository =
    IdentityRecordRepository(
      storage =
        WriteOnceIdentityRecordStorage(
          AndroidDurableIdentityFileOps(File(context.noBackupFilesDir, RECORD_FILE_NAME)),
        ),
      legacy =
        SharedPreferencesLegacyIdentitySource(
          context.getSharedPreferences(LEGACY_PREFERENCES_NAME, Context.MODE_PRIVATE),
        ),
    )

  override fun hasIdentity(): Boolean = NativeIdentityVaultProcessLock.withLock {
    val record = repository.load() ?: return@withLock false
    try {
      true
    } finally {
      record.clear()
    }
  }

  fun storeNewMnemonic(mnemonic: String) = NativeIdentityVaultProcessLock.withLock {
    val plaintext = mnemonic.toByteArray(Charsets.UTF_8)
    var iv: ByteArray? = null
    var ciphertext: ByteArray? = null
    try {
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
      val encryptedIv = cipher.iv
      val encryptedCiphertext = cipher.doFinal(plaintext)
      iv = encryptedIv
      ciphertext = encryptedCiphertext
      repository.storeNew(EncryptedIdentityRecord(encryptedIv, encryptedCiphertext))
    } catch (error: IdentityVaultException) {
      throw error
    } catch (error: Exception) {
      throw IdentityVaultException("identity vault cannot be encrypted", error)
    } finally {
      iv?.fill(0)
      ciphertext?.fill(0)
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
  override fun <T> withMnemonicBytes(operation: (ByteArray) -> T): T {
    val plaintext = NativeIdentityVaultProcessLock.withLock {
      val record = repository.load() ?: throw IdentityVaultException("no local identity exists")
      try {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
          Cipher.DECRYPT_MODE,
          getExistingKey(),
          GCMParameterSpec(GCM_TAG_BITS, record.iv),
        )
        cipher.doFinal(record.ciphertext)
      } catch (error: Exception) {
        throw IdentityVaultException("identity vault cannot be decrypted", error)
      } finally {
        record.clear()
      }
    }
    return try {
      // No replace/delete path exists. Once an authenticated copy is obtained,
      // release the process transaction before Argon2/SQLCipher/native setup so
      // Activity lifecycle calls never block on expensive client creation.
      operation(plaintext)
    } finally {
      plaintext.fill(0)
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
    private const val RECORD_FILE_NAME = "veil_native_identity_v1.bin"
    private const val LEGACY_PREFERENCES_NAME = "veil_native_identity_v1"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "veil.mobile.identity.v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
  }
}

/** Read-only compatibility adapter for the legacy SharedPreferences record. */
internal class SharedPreferencesLegacyIdentitySource(
  private val preferences: SharedPreferences,
) : LegacyIdentitySource {
  override fun hasAny(): Boolean = LEGACY_KEYS.any(preferences::contains)

  override fun read(): LegacyIdentityState {
    val present = LEGACY_KEYS.count(preferences::contains)
    if (present == 0) return LegacyIdentityState.Empty
    if (present != LEGACY_KEYS.size) return LegacyIdentityState.Partial

    val version =
      try {
        preferences.getInt(KEY_VERSION, 0)
      } catch (error: ClassCastException) {
        throw IdentityVaultException("legacy identity vault version is invalid", error)
      }
    if (version != LEGACY_FORMAT_VERSION) {
      throw IdentityVaultException("unsupported legacy identity vault version")
    }

    val iv = decode(KEY_IV, MAX_LEGACY_IV_BYTES)
    try {
      val ciphertext = decode(KEY_CIPHERTEXT, MAX_LEGACY_CIPHERTEXT_BYTES)
      return LegacyIdentityState.Complete(EncryptedIdentityRecord(iv, ciphertext))
    } catch (error: Throwable) {
      iv.fill(0)
      throw error
    }
  }

  override fun clear(): Boolean = preferences.edit().clear().commit()

  private fun decode(key: String, maximumDecodedBytes: Int): ByteArray {
    val value =
      try {
        preferences.getString(key, null)
      } catch (error: ClassCastException) {
        throw IdentityVaultException("legacy identity vault encoding is invalid", error)
      } ?: throw IdentityVaultException("legacy identity vault is incomplete")

    val maximumEncodedCharacters = ((maximumDecodedBytes + 2) / 3) * 4
    if (
      value.isEmpty() ||
        value.length > maximumEncodedCharacters ||
        value.length % 4 != 0 ||
        !BASE64_PATTERN.matches(value)
    ) {
      throw IdentityVaultException("legacy identity vault encoding is invalid")
    }

    val decoded =
      try {
        Base64.decode(value, Base64.NO_WRAP)
      } catch (error: IllegalArgumentException) {
        throw IdentityVaultException("legacy identity vault encoding is invalid", error)
      }
    if (decoded.size > maximumDecodedBytes) {
      decoded.fill(0)
      throw IdentityVaultException("legacy identity vault field is too large")
    }
    return decoded
  }

  companion object {
    private const val LEGACY_FORMAT_VERSION = 1
    private const val KEY_VERSION = "version"
    private const val KEY_IV = "iv"
    private const val KEY_CIPHERTEXT = "ciphertext"
    private const val MAX_LEGACY_IV_BYTES = 32
    private const val MAX_LEGACY_CIPHERTEXT_BYTES = 8 * 1024
    private val LEGACY_KEYS = listOf(KEY_VERSION, KEY_IV, KEY_CIPHERTEXT)
    private val BASE64_PATTERN = Regex("^[A-Za-z0-9+/]*={0,2}$")
  }
}

/**
 * Process-wide serialization shared by every vault instance/React context.
 *
 * The write-once file protocol protects disk durability, while this lock makes
 * the multi-step "check empty, encrypt, commit" operation atomic between React
 * contexts.
 */
internal object NativeIdentityVaultProcessLock {
  private val lock = Any()

  fun <T> withLock(operation: () -> T): T = synchronized(lock) { operation() }
}

internal class IdentityVaultException(message: String, cause: Throwable? = null) :
  Exception(message, cause)
