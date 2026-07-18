package io.veil.mobile.crypto

import android.system.Os
import android.system.OsConstants
import java.io.Closeable
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream

/** An owned encrypted identity record. Call [clear] as soon as it is no longer needed. */
internal class EncryptedIdentityRecord(
  val iv: ByteArray,
  val ciphertext: ByteArray,
) {
  fun clear() {
    iv.fill(0)
    ciphertext.fill(0)
  }
}

/**
 * Strict, bounded on-disk format for one AES-GCM identity record.
 *
 * Layout (big endian): magic[8], version:u8, flags:u8, ivLength:u16,
 * ciphertextLength:u32, iv, ciphertext. No extension or trailing bytes are
 * accepted so a future format cannot be interpreted accidentally as v1.
 */
internal object IdentityVaultRecordCodec {
  private val MAGIC = byteArrayOf(0x56, 0x45, 0x49, 0x4c, 0x49, 0x44, 0x45, 0x4e)
  private const val FORMAT_VERSION = 1
  private const val FLAGS_NONE = 0
  private const val HEADER_BYTES = 16
  private const val GCM_IV_BYTES = 12
  private const val GCM_TAG_BYTES = 16
  private const val MAX_CIPHERTEXT_BYTES = 8 * 1024

  const val MAX_ENCODED_BYTES = HEADER_BYTES + GCM_IV_BYTES + MAX_CIPHERTEXT_BYTES

  fun encode(record: EncryptedIdentityRecord): ByteArray {
    validateLengths(record.iv.size, record.ciphertext.size)
    val encoded = ByteArray(HEADER_BYTES + record.iv.size + record.ciphertext.size)
    MAGIC.copyInto(encoded, destinationOffset = 0)
    encoded[8] = FORMAT_VERSION.toByte()
    encoded[9] = FLAGS_NONE.toByte()
    putUnsignedShort(encoded, 10, record.iv.size)
    putUnsignedInt(encoded, 12, record.ciphertext.size)
    record.iv.copyInto(encoded, destinationOffset = HEADER_BYTES)
    record.ciphertext.copyInto(encoded, destinationOffset = HEADER_BYTES + record.iv.size)
    return encoded
  }

  fun decode(encoded: ByteArray): EncryptedIdentityRecord {
    if (encoded.size < HEADER_BYTES) {
      throw IdentityVaultException("identity vault record is truncated")
    }
    for (index in MAGIC.indices) {
      if (encoded[index] != MAGIC[index]) {
        throw IdentityVaultException("identity vault record magic is invalid")
      }
    }
    val version = encoded[8].toInt() and 0xff
    if (version != FORMAT_VERSION) {
      throw IdentityVaultException("unsupported identity vault record version")
    }
    if ((encoded[9].toInt() and 0xff) != FLAGS_NONE) {
      throw IdentityVaultException("identity vault record flags are invalid")
    }

    val ivLength = readUnsignedShort(encoded, 10)
    val ciphertextLength = readUnsignedInt(encoded, 12)
    if (ciphertextLength > Int.MAX_VALUE.toLong()) {
      throw IdentityVaultException("identity vault ciphertext is too large")
    }
    validateLengths(ivLength, ciphertextLength.toInt())

    val expectedLength = HEADER_BYTES.toLong() + ivLength + ciphertextLength
    when {
      encoded.size.toLong() < expectedLength ->
        throw IdentityVaultException("identity vault record is truncated")
      encoded.size.toLong() > expectedLength ->
        throw IdentityVaultException("identity vault record has trailing bytes")
    }

    val iv = encoded.copyOfRange(HEADER_BYTES, HEADER_BYTES + ivLength)
    val ciphertext =
      encoded.copyOfRange(
        HEADER_BYTES + ivLength,
        HEADER_BYTES + ivLength + ciphertextLength.toInt(),
      )
    return EncryptedIdentityRecord(iv, ciphertext)
  }

  private fun validateLengths(ivLength: Int, ciphertextLength: Int) {
    if (ivLength != GCM_IV_BYTES) {
      throw IdentityVaultException("identity vault IV length is invalid")
    }
    if (ciphertextLength < GCM_TAG_BYTES) {
      throw IdentityVaultException("identity vault ciphertext is truncated")
    }
    if (ciphertextLength > MAX_CIPHERTEXT_BYTES) {
      throw IdentityVaultException("identity vault ciphertext is too large")
    }
  }

  private fun putUnsignedShort(target: ByteArray, offset: Int, value: Int) {
    target[offset] = (value ushr 8).toByte()
    target[offset + 1] = value.toByte()
  }

  private fun putUnsignedInt(target: ByteArray, offset: Int, value: Int) {
    target[offset] = (value ushr 24).toByte()
    target[offset + 1] = (value ushr 16).toByte()
    target[offset + 2] = (value ushr 8).toByte()
    target[offset + 3] = value.toByte()
  }

  private fun readUnsignedShort(source: ByteArray, offset: Int): Int =
    ((source[offset].toInt() and 0xff) shl 8) or (source[offset + 1].toInt() and 0xff)

  private fun readUnsignedInt(source: ByteArray, offset: Int): Long =
    ((source[offset].toLong() and 0xff) shl 24) or
      ((source[offset + 1].toLong() and 0xff) shl 16) or
      ((source[offset + 2].toLong() and 0xff) shl 8) or
      (source[offset + 3].toLong() and 0xff)
}

internal interface IdentityRecordStorage {
  /** Returns an owned record byte array, or null only when no durable record exists. */
  fun readOrNull(): ByteArray?

  fun write(encoded: ByteArray)
}

internal interface DurableIdentityTempOutput : Closeable {
  fun write(bytes: ByteArray)

  fun flush()

  fun sync()
}

/** File-operation seam for deterministic crash and durability tests on the JVM. */
internal interface DurableIdentityFileOps {
  fun baseExists(): Boolean

  fun tempExists(): Boolean

  fun deleteTemp()

  fun openTempExclusively(): DurableIdentityTempOutput

  fun openTemp(): InputStream

  /** Atomically publishes temp while refusing to replace an existing base identity. */
  fun publishTempToBaseIfAbsent()

  fun syncDirectory()

  fun openBase(): InputStream
}

/**
 * Immutable single-record protocol.
 *
 * A write is successful only after `.new` is file-synced, closed and read back
 * exactly; then it is atomically hard-linked to an absent base name, the
 * directory is synced, `.new` is removed and synced, and base is read back.
 * The base identity is never overwritten or deleted.
 */
internal class WriteOnceIdentityRecordStorage(
  private val files: DurableIdentityFileOps,
) : IdentityRecordStorage {
  override fun readOrNull(): ByteArray? {
    try {
      if (files.baseExists()) {
        // If publish succeeded but its directory sync was interrupted, make
        // the base link durable before removing the remaining temp link.
        files.syncDirectory()
        if (files.tempExists()) cleanupTemp()
      } else {
        if (files.tempExists()) cleanupTemp()
        if (!files.baseExists()) return null
        files.syncDirectory()
      }
      return readBaseBounded()
    } catch (error: IdentityVaultException) {
      throw error
    } catch (error: Exception) {
      throw IdentityVaultException("identity vault record cannot be read", error)
    }
  }

  override fun write(encoded: ByteArray) {
    if (encoded.isEmpty() || encoded.size > IdentityVaultRecordCodec.MAX_ENCODED_BYTES) {
      throw IdentityVaultException("identity vault record size is invalid")
    }

    var output: DurableIdentityTempOutput? = null
    try {
      if (files.baseExists()) {
        throw IdentityVaultException("identity vault record already exists")
      }
      if (files.tempExists()) cleanupTemp()
      if (files.baseExists()) {
        throw IdentityVaultException("identity vault record already exists")
      }

      output = files.openTempExclusively()
      output.write(encoded)
      output.flush()
      output.sync()
      output.close()
      output = null

      verifyExact(files.openTemp(), encoded, "temporary")

      if (files.baseExists()) {
        throw IdentityVaultException("identity vault record already exists")
      }
      files.publishTempToBaseIfAbsent()
      if (!files.baseExists()) {
        throw IdentityVaultException("identity vault publish did not commit")
      }
      files.syncDirectory()
      if (!files.tempExists()) {
        throw IdentityVaultException("identity vault temporary link disappeared early")
      }
      cleanupTemp()

      verifyExact(files.openBase(), encoded, "base")
    } catch (error: Throwable) {
      output?.let { pending ->
        try {
          pending.close()
        } catch (closeError: Throwable) {
          error.addSuppressed(closeError)
        }
      }
      // Publish may have succeeded before an error was reported. Never delete
      // base. If both links exist, sync base first, then remove only `.new`.
      try {
        if (files.tempExists()) {
          if (files.baseExists()) files.syncDirectory()
          cleanupTemp()
        }
      } catch (cleanupError: Throwable) {
        error.addSuppressed(cleanupError)
      }
      when (error) {
        is IdentityVaultException -> throw error
        is Exception ->
          throw IdentityVaultException("identity vault durable write did not commit", error)
        else -> throw error
      }
    }
  }

  private fun cleanupTemp() {
    files.deleteTemp()
    if (files.tempExists()) {
      throw IdentityVaultException("identity vault temporary record cannot be removed")
    }
    files.syncDirectory()
  }

  private fun readBaseBounded(): ByteArray {
    val input = files.openBase()
    return input.use(::readBounded)
  }

  private fun verifyExact(input: InputStream, expected: ByteArray, label: String) {
    val actual = input.use(::readBounded)
    try {
      if (!actual.contentEquals(expected)) {
        throw IdentityVaultException("identity vault $label read-back verification failed")
      }
    } finally {
      actual.fill(0)
    }
  }

  private fun readBounded(input: InputStream): ByteArray {
    val scratch = ByteArray(IdentityVaultRecordCodec.MAX_ENCODED_BYTES + 1)
    var count = 0
    try {
      while (count < scratch.size) {
        val read = input.read(scratch, count, scratch.size - count)
        if (read < 0) break
        if (read == 0) {
          val single = input.read()
          if (single < 0) break
          scratch[count++] = single.toByte()
        } else {
          count += read
        }
      }
      if (count == 0) throw IdentityVaultException("identity vault record is empty")
      if (count > IdentityVaultRecordCodec.MAX_ENCODED_BYTES) {
        throw IdentityVaultException("identity vault record is too large")
      }
      return scratch.copyOf(count)
    } finally {
      scratch.fill(0)
    }
  }
}

internal class AndroidDurableIdentityFileOps(baseFile: File) : DurableIdentityFileOps {
  private val base = baseFile
  private val temp = File(baseFile.parentFile, baseFile.name + ".new")
  private val parent =
    baseFile.parentFile ?: throw IdentityVaultException("identity vault directory is unavailable")

  override fun baseExists(): Boolean = base.exists()

  override fun tempExists(): Boolean = temp.exists()

  override fun deleteTemp() {
    if (temp.exists()) Os.remove(temp.absolutePath)
  }

  override fun openTempExclusively(): DurableIdentityTempOutput {
    val descriptor =
      Os.open(
        temp.absolutePath,
        OsConstants.O_WRONLY or
          OsConstants.O_CREAT or
          OsConstants.O_EXCL or
          LINUX_O_CLOEXEC,
        OsConstants.S_IRUSR or OsConstants.S_IWUSR,
      )
    return try {
      AndroidDurableIdentityTempOutput(FileOutputStream(descriptor))
    } catch (error: Throwable) {
      try {
        Os.close(descriptor)
      } catch (closeError: Throwable) {
        error.addSuppressed(closeError)
      }
      throw error
    }
  }

  override fun openTemp(): InputStream = FileInputStream(temp)

  override fun publishTempToBaseIfAbsent() {
    // link(2) fails with EEXIST atomically; unlike rename(2), it can never
    // replace an identity created by another process between our checks.
    Os.link(temp.absolutePath, base.absolutePath)
    if (!base.exists() || !temp.exists()) {
      throw IOException("identity vault publish result is invalid")
    }
  }

  override fun syncDirectory() {
    val descriptor =
      Os.open(
        parent.absolutePath,
        OsConstants.O_RDONLY or LINUX_O_CLOEXEC,
        0,
      )
    var failure: Throwable? = null
    try {
      Os.fsync(descriptor)
    } catch (error: Throwable) {
      failure = error
      throw error
    } finally {
      try {
        Os.close(descriptor)
      } catch (closeError: Throwable) {
        failure?.addSuppressed(closeError) ?: throw closeError
      }
    }
  }

  override fun openBase(): InputStream = FileInputStream(base)
}

// O_CLOEXEC is part of the Linux UAPI used by every supported Android ABI
// from API 24, but android.system.OsConstants only exposes the Java field from
// API 27. Keep the atomic open(2) flag without linking that newer Java field.
private const val LINUX_O_CLOEXEC = 0x00080000

private class AndroidDurableIdentityTempOutput(
  private val output: FileOutputStream,
) : DurableIdentityTempOutput {
  override fun write(bytes: ByteArray) = output.write(bytes)

  override fun flush() = output.flush()

  override fun sync() = output.fd.sync()

  override fun close() = output.close()
}

internal sealed interface LegacyIdentityState {
  data object Empty : LegacyIdentityState

  data object Partial : LegacyIdentityState

  class Complete(val record: EncryptedIdentityRecord) : LegacyIdentityState
}

internal interface LegacyIdentitySource {
  /** Does not parse legacy values; used only to retry cleanup after migration. */
  fun hasAny(): Boolean

  fun read(): LegacyIdentityState

  /** Returns true only after the legacy data is durably removed. */
  fun clear(): Boolean
}

/** Coordinates authoritative durable reads and one-way legacy migration. */
internal class IdentityRecordRepository(
  private val storage: IdentityRecordStorage,
  private val legacy: LegacyIdentitySource,
) {
  /** Returns an owned record which the caller must clear. */
  fun load(): EncryptedIdentityRecord? {
    storage.readOrNull()?.let { encoded ->
      val record =
        try {
          IdentityVaultRecordCodec.decode(encoded)
        } finally {
          encoded.fill(0)
        }
      // The verified durable record is authoritative. Cleanup must never turn
      // it into a load failure; a later load retries if this attempt fails.
      bestEffortLegacyCleanup(knownPresent = false)
      return record
    }

    return when (val state = legacy.read()) {
      LegacyIdentityState.Empty -> null
      LegacyIdentityState.Partial ->
        throw IdentityVaultException("legacy identity vault is incomplete")
      is LegacyIdentityState.Complete -> migrate(state.record)
    }
  }

  fun storeNew(record: EncryptedIdentityRecord) {
    load()?.let { existing ->
      existing.clear()
      throw IdentityVaultException("an identity already exists on this device")
    }
    writeRecord(record)
  }

  private fun migrate(record: EncryptedIdentityRecord): EncryptedIdentityRecord {
    try {
      writeRecord(record)
      bestEffortLegacyCleanup(knownPresent = true)
      return record
    } catch (error: Throwable) {
      record.clear()
      throw error
    }
  }

  private fun bestEffortLegacyCleanup(knownPresent: Boolean) {
    val shouldClear =
      if (knownPresent) {
        true
      } else {
        try {
          legacy.hasAny()
        } catch (_: Exception) {
          false
        }
      }
    if (!shouldClear) return
    try {
      legacy.clear()
    } catch (_: Exception) {
      // The verified durable file remains authoritative. Retry on next load.
    }
  }

  private fun writeRecord(record: EncryptedIdentityRecord) {
    val encoded = IdentityVaultRecordCodec.encode(record)
    try {
      storage.write(encoded)
    } finally {
      encoded.fill(0)
    }
  }
}
