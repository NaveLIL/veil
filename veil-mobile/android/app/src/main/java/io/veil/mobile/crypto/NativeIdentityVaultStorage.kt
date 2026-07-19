package io.veil.mobile.crypto

import android.system.ErrnoException
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

  /** Makes the staged record name durable before publication. */
  fun syncTempDirectory()

  /**
   * Atomically publishes a non-empty staging directory at the base path.
   *
   * The base path may already be the legacy regular-file format. A conforming
   * implementation must never replace that file or a previously published,
   * non-empty directory.
   */
  fun publishTempToBaseIfAbsent()

  fun syncDirectory()

  fun openBase(): InputStream
}

/**
 * Immutable single-record protocol.
 *
 * A write is successful only after the record inside `.new` is file-synced,
 * closed and read back exactly. The staging directory and its parent are then
 * synced before the non-empty directory is atomically renamed to the base
 * path. The parent is synced again and the published record is read back.
 *
 * Older builds stored the encoded record directly at the same base path. New
 * builds use a non-empty directory there. POSIX rename cannot replace either
 * a legacy regular file with a directory or an existing non-empty directory,
 * so both formats retain the same write-once namespace without link(2), which
 * Android SELinux may deny inside an otherwise writable app sandbox.
 */
internal class WriteOnceIdentityRecordStorage(
  private val files: DurableIdentityFileOps,
) : IdentityRecordStorage {
  override fun readOrNull(): ByteArray? {
    try {
      if (files.baseExists()) {
        // If publish succeeded but its directory sync was interrupted, make
        // the base name durable before removing any stale staging directory.
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
      files.syncTempDirectory()
      // Persist the staging directory entry before rename. If power is lost
      // before the post-rename sync, recovery sees either this old name or the
      // published base name, never a partially written published record.
      files.syncDirectory()

      if (files.baseExists()) {
        throw IdentityVaultException("identity vault record already exists")
      }
      files.publishTempToBaseIfAbsent()
      if (!files.baseExists()) {
        throw IdentityVaultException("identity vault publish did not commit")
      }
      files.syncDirectory()
      if (files.tempExists()) {
        throw IdentityVaultException("identity vault staging directory remained after publish")
      }

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
      // base. Remove only an unpublished staging directory that still exists.
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
  private val tempRecord = File(temp, PUBLISHED_RECORD_FILE_NAME)
  private val parent =
    baseFile.parentFile ?: throw IdentityVaultException("identity vault directory is unavailable")

  override fun baseExists(): Boolean = pathExists(base)

  override fun tempExists(): Boolean = pathExists(temp)

  override fun deleteTemp() {
    val mode = lstatModeOrNull(temp) ?: return
    when {
      OsConstants.S_ISREG(mode) -> {
        // Read compatibility includes cleanup of a `.new` regular file left
        // by the former hard-link publication protocol.
        Os.remove(temp.absolutePath)
      }
      OsConstants.S_ISDIR(mode) -> {
        val children = listDirectoryStrict(temp, "identity vault staging directory")
        if (children.isNotEmpty()) {
          if (children.size != 1 || children.single() != PUBLISHED_RECORD_FILE_NAME) {
            throw IdentityVaultException("identity vault staging directory is invalid")
          }
          requireRegularFile(tempRecord, "identity vault staged record")
          Os.remove(tempRecord.absolutePath)
        }
        Os.remove(temp.absolutePath)
      }
      else -> throw IdentityVaultException("identity vault staging path type is invalid")
    }
  }

  override fun openTempExclusively(): DurableIdentityTempOutput {
    Os.mkdir(
      temp.absolutePath,
      OsConstants.S_IRUSR or OsConstants.S_IWUSR or OsConstants.S_IXUSR,
    )
    val descriptor =
      Os.open(
        tempRecord.absolutePath,
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

  override fun openTemp(): InputStream {
    requirePublishedDirectory(temp, "identity vault staging directory")
    return FileInputStream(tempRecord)
  }

  override fun syncTempDirectory() {
    requirePublishedDirectory(temp, "identity vault staging directory")
    syncDirectoryPath(temp)
  }

  override fun publishTempToBaseIfAbsent() {
    requirePublishedDirectory(temp, "identity vault staging directory")
    // Both supported base layouts reject this rename atomically if another
    // writer wins: a directory cannot replace the legacy regular file, and a
    // non-empty directory cannot replace the published directory layout.
    Os.rename(temp.absolutePath, base.absolutePath)
    if (!pathExists(base) || pathExists(temp)) {
      throw IOException("identity vault publish result is invalid")
    }
    requireReadableBaseLayout()
  }

  override fun syncDirectory() {
    syncDirectoryPath(parent)
  }

  override fun openBase(): InputStream {
    return when (val mode = lstatModeOrNull(base)) {
      null -> throw IdentityVaultException("identity vault record is unavailable")
      else -> when {
        OsConstants.S_ISREG(mode) -> FileInputStream(base)
        OsConstants.S_ISDIR(mode) -> {
          requirePublishedDirectory(base, "identity vault published directory")
          FileInputStream(File(base, PUBLISHED_RECORD_FILE_NAME))
        }
        else -> throw IdentityVaultException("identity vault base path type is invalid")
      }
    }
  }

  private fun requireReadableBaseLayout() {
    val mode = lstatModeOrNull(base)
      ?: throw IdentityVaultException("identity vault record is unavailable")
    when {
      OsConstants.S_ISREG(mode) -> Unit
      OsConstants.S_ISDIR(mode) ->
        requirePublishedDirectory(base, "identity vault published directory")
      else -> throw IdentityVaultException("identity vault base path type is invalid")
    }
  }

  private fun requirePublishedDirectory(directory: File, label: String) {
    val mode = lstatModeOrNull(directory)
      ?: throw IdentityVaultException("$label is unavailable")
    if (!OsConstants.S_ISDIR(mode)) {
      throw IdentityVaultException("$label type is invalid")
    }
    val children = listDirectoryStrict(directory, label)
    if (children.size != 1 || children.single() != PUBLISHED_RECORD_FILE_NAME) {
      throw IdentityVaultException("$label contents are invalid")
    }
    requireRegularFile(File(directory, PUBLISHED_RECORD_FILE_NAME), "$label record")
  }

  private fun requireRegularFile(file: File, label: String) {
    val mode = lstatModeOrNull(file)
      ?: throw IdentityVaultException("$label is unavailable")
    if (!OsConstants.S_ISREG(mode)) {
      throw IdentityVaultException("$label type is invalid")
    }
  }

  private fun listDirectoryStrict(directory: File, label: String): List<String> =
    directory.list()?.toList() ?: throw IdentityVaultException("$label cannot be listed")

  private fun pathExists(file: File): Boolean = lstatModeOrNull(file) != null

  private fun lstatModeOrNull(file: File): Int? =
    try {
      Os.lstat(file.absolutePath).st_mode
    } catch (error: ErrnoException) {
      if (error.errno == OsConstants.ENOENT) null else throw error
    }

  private fun syncDirectoryPath(directory: File) {
    val descriptor =
      Os.open(
        directory.absolutePath,
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

  companion object {
    private const val PUBLISHED_RECORD_FILE_NAME = "record.bin"
  }
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
