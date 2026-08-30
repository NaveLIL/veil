package io.veil.mobile.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
      WriteOnceIdentityRecordStorage(
        AndroidDurableIdentityFileOps(File(context.noBackupFilesDir, RECORD_FILE_NAME)),
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

  /**
   * Durably stores a newly provisioned mnemonic without ever materializing it
   * as an immutable JVM [String]. The caller retains ownership of
   * [mnemonicUtf8] and must clear it; this vault encrypts a private copy and
   * clears that copy before returning.
  */
  fun storeNewMnemonicBytes(mnemonicUtf8: ByteArray) = NativeIdentityVaultProcessLock.withLock {
    require(mnemonicUtf8.size in 1..MAX_MNEMONIC_BYTES) { "mnemonic byte length is invalid" }
    val plaintext = mnemonicUtf8.copyOf()
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
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "veil.mobile.identity.v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val MAX_MNEMONIC_BYTES = 24 * 9
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
