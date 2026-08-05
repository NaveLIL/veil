package io.veil.mobile.recovery

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.Closeable
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.UUID

/** A fail-closed failure at the durable, non-secret setup-journal boundary. */
internal class NativeIdentitySetupJournalException(
  message: String,
  cause: Throwable? = null,
) : IOException(message, cause)

internal enum class NativeIdentitySetupJournalMode(internal val wireValue: Int) {
  CREATE(1),
  RESTORE(2),
  ;

  companion object {
    fun fromWire(value: Int): NativeIdentitySetupJournalMode? = entries.find { it.wireValue == value }
  }
}

internal enum class NativeIdentitySetupJournalPhase(internal val wireValue: Int) {
  PREPARED(1),
  ACTIVE(2),
  COMMITTING(3),
  TERMINAL(4),
  ;

  companion object {
    fun fromWire(value: Int): NativeIdentitySetupJournalPhase? = entries.find { it.wireValue == value }
  }
}

/**
 * The complete terminal vocabulary. It deliberately carries no diagnostic,
 * error text, identity material, account data, Node origin, or access pass.
 */
internal enum class NativeIdentitySetupJournalOutcome(internal val wireValue: Int) {
  COMMITTED(1),
  USER_CANCELLED(2),
  INTERRUPTED(3),
  ;

  companion object {
    fun fromWire(value: Int): NativeIdentitySetupJournalOutcome? =
      entries.find { it.wireValue == value }
  }
}

/**
 * Fixed-schema non-secret receipt for one native identity-setup attempt.
 *
 * UUIDs are random correlation capabilities, not account/device identifiers.
 * The record has no extensible string or byte-array field through which a
 * phrase, seed, key, identity, origin, pass, or diagnostic could be persisted.
 */
internal class NativeIdentitySetupJournalRecord private constructor(
  val attemptId: UUID,
  val processIncarnationId: UUID,
  val mode: NativeIdentitySetupJournalMode,
  val phase: NativeIdentitySetupJournalPhase,
  val outcome: NativeIdentitySetupJournalOutcome?,
  val revision: Int,
) {
  init {
    validateRandomUuid(attemptId)
    validateRandomUuid(processIncarnationId)
    if (attemptId == processIncarnationId) {
      throw NativeIdentitySetupJournalException("setup journal correlation identifiers conflict")
    }
    validateShape(phase, outcome, revision)
  }

  internal fun successor(
    nextPhase: NativeIdentitySetupJournalPhase,
    nextOutcome: NativeIdentitySetupJournalOutcome?,
    writerProcessIncarnationId: UUID,
  ): NativeIdentitySetupJournalRecord {
    val nextRevision = revision + 1
    if (!isAllowedSuccessor(nextPhase, nextOutcome, nextRevision)) {
      throw NativeIdentitySetupJournalException("setup journal transition is invalid")
    }
    return create(
      attemptId = attemptId,
      processIncarnationId = writerProcessIncarnationId,
      mode = mode,
      phase = nextPhase,
      outcome = nextOutcome,
      revision = nextRevision,
    )
  }

  internal fun isAllowedSuccessor(candidate: NativeIdentitySetupJournalRecord): Boolean =
    attemptId == candidate.attemptId &&
      mode == candidate.mode &&
      isAllowedSuccessor(candidate.phase, candidate.outcome, candidate.revision)

  private fun isAllowedSuccessor(
    nextPhase: NativeIdentitySetupJournalPhase,
    nextOutcome: NativeIdentitySetupJournalOutcome?,
    nextRevision: Int,
  ): Boolean {
    if (nextRevision != revision + 1) return false
    return when (phase) {
      NativeIdentitySetupJournalPhase.PREPARED ->
        (nextPhase == NativeIdentitySetupJournalPhase.ACTIVE && nextOutcome == null) ||
          (nextPhase == NativeIdentitySetupJournalPhase.TERMINAL &&
            nextOutcome == NativeIdentitySetupJournalOutcome.INTERRUPTED)
      NativeIdentitySetupJournalPhase.ACTIVE ->
        (nextPhase == NativeIdentitySetupJournalPhase.COMMITTING && nextOutcome == null) ||
          (nextPhase == NativeIdentitySetupJournalPhase.TERMINAL &&
            (nextOutcome == NativeIdentitySetupJournalOutcome.USER_CANCELLED ||
              nextOutcome == NativeIdentitySetupJournalOutcome.INTERRUPTED))
      NativeIdentitySetupJournalPhase.COMMITTING ->
        nextPhase == NativeIdentitySetupJournalPhase.TERMINAL &&
          (nextOutcome == NativeIdentitySetupJournalOutcome.COMMITTED ||
            nextOutcome == NativeIdentitySetupJournalOutcome.INTERRUPTED)
      NativeIdentitySetupJournalPhase.TERMINAL -> false
    }
  }

  override fun equals(other: Any?): Boolean =
    other is NativeIdentitySetupJournalRecord &&
      attemptId == other.attemptId &&
      processIncarnationId == other.processIncarnationId &&
      mode == other.mode &&
      phase == other.phase &&
      outcome == other.outcome &&
      revision == other.revision

  override fun hashCode(): Int {
    var result = attemptId.hashCode()
    result = 31 * result + processIncarnationId.hashCode()
    result = 31 * result + mode.hashCode()
    result = 31 * result + phase.hashCode()
    result = 31 * result + (outcome?.hashCode() ?: 0)
    return 31 * result + revision
  }

  /** Avoid making correlation identifiers attractive accidental log payloads. */
  override fun toString(): String = "NativeIdentitySetupJournalRecord(redacted)"

  companion object {
    internal fun prepared(
      attemptId: UUID,
      processIncarnationId: UUID,
      mode: NativeIdentitySetupJournalMode,
    ): NativeIdentitySetupJournalRecord =
      create(
        attemptId = attemptId,
        processIncarnationId = processIncarnationId,
        mode = mode,
        phase = NativeIdentitySetupJournalPhase.PREPARED,
        outcome = null,
        revision = 1,
      )

    internal fun decoded(
      attemptId: UUID,
      processIncarnationId: UUID,
      mode: NativeIdentitySetupJournalMode,
      phase: NativeIdentitySetupJournalPhase,
      outcome: NativeIdentitySetupJournalOutcome?,
      revision: Int,
    ): NativeIdentitySetupJournalRecord =
      create(attemptId, processIncarnationId, mode, phase, outcome, revision)

    private fun create(
      attemptId: UUID,
      processIncarnationId: UUID,
      mode: NativeIdentitySetupJournalMode,
      phase: NativeIdentitySetupJournalPhase,
      outcome: NativeIdentitySetupJournalOutcome?,
      revision: Int,
    ): NativeIdentitySetupJournalRecord =
      NativeIdentitySetupJournalRecord(
        attemptId,
        processIncarnationId,
        mode,
        phase,
        outcome,
        revision,
      )

    private fun validateRandomUuid(value: UUID) {
      if (value.version() != RANDOM_UUID_VERSION || value.variant() != IETF_UUID_VARIANT) {
        throw NativeIdentitySetupJournalException("setup journal correlation identifier is invalid")
      }
    }

    private fun validateShape(
      phase: NativeIdentitySetupJournalPhase,
      outcome: NativeIdentitySetupJournalOutcome?,
      revision: Int,
    ) {
      val shapeValid = when (phase) {
        NativeIdentitySetupJournalPhase.PREPARED -> revision == 1 && outcome == null
        NativeIdentitySetupJournalPhase.ACTIVE -> revision == 2 && outcome == null
        NativeIdentitySetupJournalPhase.COMMITTING -> revision == 3 && outcome == null
        NativeIdentitySetupJournalPhase.TERMINAL -> when (revision) {
          2 -> outcome == NativeIdentitySetupJournalOutcome.INTERRUPTED
          3 ->
            outcome == NativeIdentitySetupJournalOutcome.USER_CANCELLED ||
              outcome == NativeIdentitySetupJournalOutcome.INTERRUPTED
          4 ->
            outcome == NativeIdentitySetupJournalOutcome.COMMITTED ||
              outcome == NativeIdentitySetupJournalOutcome.INTERRUPTED
          else -> false
        }
      }
      if (!shapeValid) {
        throw NativeIdentitySetupJournalException("setup journal phase shape is invalid")
      }
    }

    private const val RANDOM_UUID_VERSION = 4
    private const val IETF_UUID_VARIANT = 2
  }
}

/**
 * Strict v1 codec. Layout (big endian):
 *
 * magic[8], version:u8, flags:u8, mode:u8, phase:u8, outcome:u8,
 * revision:u8, reserved[2], attempt_id[16], process_incarnation_id[16],
 * sha256[32]. The digest covers every preceding byte.
 */
internal object NativeIdentitySetupJournalCodec {
  private val MAGIC =
    byteArrayOf(0x56, 0x45, 0x49, 0x4c, 0x49, 0x53, 0x4a, 0x00)
  internal const val VERSION_OFFSET = 8
  internal const val FLAGS_OFFSET = 9
  internal const val MODE_OFFSET = 10
  internal const val PHASE_OFFSET = 11
  internal const val OUTCOME_OFFSET = 12
  internal const val REVISION_OFFSET = 13
  internal const val RESERVED_OFFSET = 14
  internal const val ATTEMPT_ID_OFFSET = 16
  internal const val PROCESS_ID_OFFSET = 32
  internal const val HASH_OFFSET = 48
  private const val FORMAT_VERSION = 1
  private const val FLAGS_NONE = 0
  private const val OUTCOME_NONE = 0
  internal const val MAX_ENCODED_BYTES = 80

  fun encode(record: NativeIdentitySetupJournalRecord): ByteArray {
    val encoded = ByteArray(MAX_ENCODED_BYTES)
    MAGIC.copyInto(encoded)
    encoded[VERSION_OFFSET] = FORMAT_VERSION.toByte()
    encoded[FLAGS_OFFSET] = FLAGS_NONE.toByte()
    encoded[MODE_OFFSET] = record.mode.wireValue.toByte()
    encoded[PHASE_OFFSET] = record.phase.wireValue.toByte()
    encoded[OUTCOME_OFFSET] = (record.outcome?.wireValue ?: OUTCOME_NONE).toByte()
    encoded[REVISION_OFFSET] = record.revision.toByte()
    putUuid(encoded, ATTEMPT_ID_OFFSET, record.attemptId)
    putUuid(encoded, PROCESS_ID_OFFSET, record.processIncarnationId)
    val digest = digestPrefix(encoded)
    try {
      digest.copyInto(encoded, destinationOffset = HASH_OFFSET)
    } finally {
      digest.fill(0)
    }
    return encoded
  }

  fun decode(encoded: ByteArray): NativeIdentitySetupJournalRecord {
    when {
      encoded.size < MAX_ENCODED_BYTES ->
        throw NativeIdentitySetupJournalException("setup journal record is truncated")
      encoded.size > MAX_ENCODED_BYTES ->
        throw NativeIdentitySetupJournalException("setup journal record has trailing bytes")
    }
    for (index in MAGIC.indices) {
      if (encoded[index] != MAGIC[index]) {
        throw NativeIdentitySetupJournalException("setup journal record magic is invalid")
      }
    }
    if (unsigned(encoded[VERSION_OFFSET]) != FORMAT_VERSION) {
      throw NativeIdentitySetupJournalException("setup journal record version is unsupported")
    }
    if (unsigned(encoded[FLAGS_OFFSET]) != FLAGS_NONE) {
      throw NativeIdentitySetupJournalException("setup journal record flags are invalid")
    }
    if (unsigned(encoded[RESERVED_OFFSET]) != 0 || unsigned(encoded[RESERVED_OFFSET + 1]) != 0) {
      throw NativeIdentitySetupJournalException("setup journal record reserved bytes are invalid")
    }

    val mode = NativeIdentitySetupJournalMode.fromWire(unsigned(encoded[MODE_OFFSET]))
      ?: throw NativeIdentitySetupJournalException("setup journal mode is invalid")
    val phase = NativeIdentitySetupJournalPhase.fromWire(unsigned(encoded[PHASE_OFFSET]))
      ?: throw NativeIdentitySetupJournalException("setup journal phase is invalid")
    val outcomeValue = unsigned(encoded[OUTCOME_OFFSET])
    val outcome = when (outcomeValue) {
      OUTCOME_NONE -> null
      else -> NativeIdentitySetupJournalOutcome.fromWire(outcomeValue)
        ?: throw NativeIdentitySetupJournalException("setup journal outcome is invalid")
    }
    val revision = unsigned(encoded[REVISION_OFFSET])
    val attemptId = readUuid(encoded, ATTEMPT_ID_OFFSET)
    val processId = readUuid(encoded, PROCESS_ID_OFFSET)

    val expectedHash = encoded.copyOfRange(HASH_OFFSET, MAX_ENCODED_BYTES)
    val actualHash = digestPrefix(encoded)
    try {
      if (!MessageDigest.isEqual(expectedHash, actualHash)) {
        throw NativeIdentitySetupJournalException("setup journal record checksum is invalid")
      }
    } finally {
      expectedHash.fill(0)
      actualHash.fill(0)
    }

    return NativeIdentitySetupJournalRecord.decoded(
      attemptId = attemptId,
      processIncarnationId = processId,
      mode = mode,
      phase = phase,
      outcome = outcome,
      revision = revision,
    )
  }

  private fun digestPrefix(encoded: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").run {
      update(encoded, 0, HASH_OFFSET)
      digest()
    }

  private fun putUuid(target: ByteArray, offset: Int, value: UUID) {
    putLong(target, offset, value.mostSignificantBits)
    putLong(target, offset + Long.SIZE_BYTES, value.leastSignificantBits)
  }

  private fun readUuid(source: ByteArray, offset: Int): UUID =
    UUID(readLong(source, offset), readLong(source, offset + Long.SIZE_BYTES))

  private fun putLong(target: ByteArray, offset: Int, value: Long) {
    for (index in 0 until Long.SIZE_BYTES) {
      target[offset + index] = (value ushr ((Long.SIZE_BYTES - 1 - index) * 8)).toByte()
    }
  }

  private fun readLong(source: ByteArray, offset: Int): Long {
    var value = 0L
    for (index in 0 until Long.SIZE_BYTES) {
      value = (value shl 8) or unsigned(source[offset + index]).toLong()
    }
    return value
  }

  private fun unsigned(value: Byte): Int = value.toInt() and 0xff
}

internal fun interface NativeIdentitySetupJournalIdSource {
  fun nextId(): UUID
}

internal object SecureNativeIdentitySetupJournalIdSource : NativeIdentitySetupJournalIdSource {
  override fun nextId(): UUID = UUID.randomUUID()
}

internal interface NativeIdentitySetupJournalTempOutput : Closeable {
  fun write(bytes: ByteArray)

  fun flush()

  fun sync()
}

/** Low-level seam used for deterministic JVM crash/fault tests. */
internal interface NativeIdentitySetupJournalFileOps {
  fun <T> withExclusiveLock(operation: () -> T): T

  fun baseExists(): Boolean

  fun tempExists(): Boolean

  fun openTempExclusively(): NativeIdentitySetupJournalTempOutput

  fun openTemp(): InputStream

  fun openBase(): InputStream

  /** Fsyncs the already validated staging inode before crash-recovery promotion. */
  fun syncTemp()

  /** Atomically renames temp to base, replacing base only when [expectBase] is true. */
  fun renameTempToBase(expectBase: Boolean)

  fun deleteTemp()

  fun deleteBase()

  fun syncDirectory()
}

/** Minimal state-machine seam used by the host-only setup reconciler. */
internal interface NativeIdentitySetupJournalAccess {
  val processIncarnationId: UUID

  fun readOrNull(): NativeIdentitySetupJournalRecord?

  fun transition(
    expected: NativeIdentitySetupJournalRecord,
    nextPhase: NativeIdentitySetupJournalPhase,
    outcome: NativeIdentitySetupJournalOutcome? = null,
  ): NativeIdentitySetupJournalRecord
}

/**
 * Durable journal state machine. The production caller must pass a directory
 * rooted at `Context.noBackupFilesDir`; the core deliberately accepts a File
 * so host JVM tests need no Android Context and integration cannot fall back
 * to backed-up SharedPreferences.
 */
internal class NativeIdentitySetupJournal(
  directory: File,
  private val idSource: NativeIdentitySetupJournalIdSource =
    SecureNativeIdentitySetupJournalIdSource,
  private val files: NativeIdentitySetupJournalFileOps =
    AndroidNativeIdentitySetupJournalFileOps(directory),
) : NativeIdentitySetupJournalAccess {
  override val processIncarnationId: UUID = nextRandomId(disallowed = null)

  override fun readOrNull(): NativeIdentitySetupJournalRecord? = locked {
    readRecoveringStagedWrite()
  }

  fun begin(mode: NativeIdentitySetupJournalMode): NativeIdentitySetupJournalRecord = locked {
    if (readRecoveringStagedWrite() != null) {
      throw NativeIdentitySetupJournalException("setup journal attempt already exists")
    }
    val attemptId = nextRandomId(disallowed = processIncarnationId)
    val prepared =
      NativeIdentitySetupJournalRecord.prepared(attemptId, processIncarnationId, mode)
    persist(expected = null, next = prepared)
    prepared
  }

  override fun transition(
    expected: NativeIdentitySetupJournalRecord,
    nextPhase: NativeIdentitySetupJournalPhase,
    outcome: NativeIdentitySetupJournalOutcome?,
  ): NativeIdentitySetupJournalRecord = locked {
    val current = readRecoveringStagedWrite()
      ?: throw NativeIdentitySetupJournalException("setup journal attempt is unavailable")
    if (current != expected) {
      throw NativeIdentitySetupJournalException("setup journal attempt changed")
    }
    val next = current.successor(nextPhase, outcome, processIncarnationId)
    persist(expected = current, next = next)
    next
  }

  /** Only an exactly matched terminal receipt can be removed. */
  fun clearTerminal(expected: NativeIdentitySetupJournalRecord) {
    if (expected.phase != NativeIdentitySetupJournalPhase.TERMINAL) {
      throw NativeIdentitySetupJournalException("unresolved setup journal cannot be cleared")
    }
    locked {
      val current = readRecoveringStagedWrite()
        ?: throw NativeIdentitySetupJournalException("setup journal attempt is unavailable")
      if (current != expected) {
        throw NativeIdentitySetupJournalException("setup journal attempt changed")
      }
      if (files.tempExists()) {
        throw NativeIdentitySetupJournalException("setup journal staging state is unresolved")
      }
      files.deleteBase()
      files.syncDirectory()
      if (files.baseExists() || files.tempExists()) {
        throw NativeIdentitySetupJournalException("setup journal clear did not commit")
      }
    }
  }

  private fun persist(
    expected: NativeIdentitySetupJournalRecord?,
    next: NativeIdentitySetupJournalRecord,
  ) {
    if (files.tempExists()) {
      throw NativeIdentitySetupJournalException("setup journal staging state is unresolved")
    }
    verifyCurrent(expected)

    val encoded = NativeIdentitySetupJournalCodec.encode(next)
    var output: NativeIdentitySetupJournalTempOutput? = null
    var renamed = false
    try {
      output = files.openTempExclusively()
      output.write(encoded)
      output.flush()
      output.sync()
      output.close()
      output = null

      verifyExact(files.openTemp(), encoded, "staged")
      // Persist the temp directory entry before the atomic rename.
      files.syncDirectory()
      verifyCurrent(expected)
      files.renameTempToBase(expectBase = expected != null)
      renamed = true
      files.syncDirectory()
      verifyExact(files.openBase(), encoded, "published")
      if (files.tempExists()) {
        throw NativeIdentitySetupJournalException("setup journal staging file remained after publish")
      }
    } catch (error: Throwable) {
      output?.let { pending ->
        try {
          pending.close()
        } catch (closeError: Throwable) {
          error.addSuppressed(closeError)
        }
      }
      if (!renamed) cleanupUnpublishedTemp(error)
      throw error
    } finally {
      encoded.fill(0)
    }
  }

  /**
   * A fully encoded temp file is a monotonic pending transition. Recovery
   * validates and re-fsyncs its inode before promotion, including when the old
   * process died before its original fsync completed. Partial, corrupt,
   * unrelated, or skipped transitions remain terminal errors and are never
   * silently deleted or interpreted as an older phase.
   */
  private fun readRecoveringStagedWrite(): NativeIdentitySetupJournalRecord? {
    if (!files.tempExists()) {
      if (!files.baseExists()) return null
      files.syncDirectory()
      return readBaseRecord()
    }

    val stagedBytes = readBounded(files.openTemp())
    try {
      val staged = NativeIdentitySetupJournalCodec.decode(stagedBytes)
      val current = if (files.baseExists()) readBaseRecord() else null
      val promotable =
        if (current == null) {
          staged.phase == NativeIdentitySetupJournalPhase.PREPARED && staged.revision == 1
        } else {
          current.isAllowedSuccessor(staged)
        }
      if (!promotable) {
        throw NativeIdentitySetupJournalException("setup journal staged transition is invalid")
      }

      files.syncTemp()
      files.renameTempToBase(expectBase = current != null)
      files.syncDirectory()
      verifyExact(files.openBase(), stagedBytes, "recovered")
      if (files.tempExists()) {
        throw NativeIdentitySetupJournalException("setup journal staging file remained after recovery")
      }
      return staged
    } finally {
      stagedBytes.fill(0)
    }
  }

  private fun verifyCurrent(expected: NativeIdentitySetupJournalRecord?) {
    val exists = files.baseExists()
    if (expected == null) {
      if (exists) throw NativeIdentitySetupJournalException("setup journal attempt already exists")
      return
    }
    if (!exists) {
      throw NativeIdentitySetupJournalException("setup journal attempt is unavailable")
    }
    if (readBaseRecord() != expected) {
      throw NativeIdentitySetupJournalException("setup journal attempt changed")
    }
  }

  private fun readBaseRecord(): NativeIdentitySetupJournalRecord {
    val encoded = readBounded(files.openBase())
    return try {
      NativeIdentitySetupJournalCodec.decode(encoded)
    } finally {
      encoded.fill(0)
    }
  }

  private fun verifyExact(input: InputStream, expected: ByteArray, label: String) {
    val actual = readBounded(input)
    try {
      if (!MessageDigest.isEqual(actual, expected)) {
        throw NativeIdentitySetupJournalException("setup journal $label read-back differs")
      }
      NativeIdentitySetupJournalCodec.decode(actual)
    } finally {
      actual.fill(0)
    }
  }

  private fun readBounded(input: InputStream): ByteArray {
    val scratch = ByteArray(NativeIdentitySetupJournalCodec.MAX_ENCODED_BYTES + 1)
    var count = 0
    try {
      input.use { source ->
        while (count < scratch.size) {
          val read = source.read(scratch, count, scratch.size - count)
          if (read < 0) break
          if (read == 0) {
            val single = source.read()
            if (single < 0) break
            scratch[count++] = single.toByte()
          } else {
            count += read
          }
        }
      }
      return scratch.copyOf(count)
    } finally {
      scratch.fill(0)
    }
  }

  private fun cleanupUnpublishedTemp(original: Throwable) {
    try {
      if (files.tempExists()) {
        files.deleteTemp()
        files.syncDirectory()
        if (files.tempExists()) {
          throw NativeIdentitySetupJournalException("setup journal staging cleanup failed")
        }
      }
    } catch (cleanupError: Throwable) {
      original.addSuppressed(cleanupError)
    }
  }

  private fun nextRandomId(disallowed: UUID?): UUID {
    repeat(MAX_RANDOM_ID_ATTEMPTS) {
      val candidate = try {
        idSource.nextId()
      } catch (error: Exception) {
        throw NativeIdentitySetupJournalException("setup journal random identifier failed", error)
      }
      if (
        candidate != disallowed &&
          candidate.version() == RANDOM_UUID_VERSION &&
          candidate.variant() == IETF_UUID_VARIANT
      ) {
        return candidate
      }
    }
    throw NativeIdentitySetupJournalException("setup journal random identifier is invalid")
  }

  private fun <T> locked(operation: () -> T): T =
    try {
      files.withExclusiveLock(operation)
    } catch (error: NativeIdentitySetupJournalException) {
      throw error
    } catch (error: Exception) {
      throw NativeIdentitySetupJournalException("setup journal I/O failed", error)
    }

  companion object {
    private const val MAX_RANDOM_ID_ATTEMPTS = 8
    private const val RANDOM_UUID_VERSION = 4
    private const val IETF_UUID_VARIANT = 2
  }
}

/** Android implementation rooted strictly at the caller-provided no-backup directory. */
internal class AndroidNativeIdentitySetupJournalFileOps(directory: File) :
  NativeIdentitySetupJournalFileOps {
  private val parent = directory
  private val base = File(directory, JOURNAL_FILE_NAME)
  private val temp = File(directory, TEMP_FILE_NAME)
  private val lock = File(directory, LOCK_FILE_NAME)

  override fun <T> withExclusiveLock(operation: () -> T): T = synchronized(PROCESS_LOCK) {
    requireDirectory(parent, "setup journal directory")
    val descriptor =
      Os.open(
        lock.absolutePath,
        OsConstants.O_RDWR or
          OsConstants.O_CREAT or
          LINUX_O_CLOEXEC or
          LINUX_O_NOFOLLOW,
        OWNER_READ_WRITE,
      )
    val stream = try {
      FileOutputStream(descriptor)
    } catch (error: Throwable) {
      try {
        Os.close(descriptor)
      } catch (closeError: Throwable) {
        error.addSuppressed(closeError)
      }
      throw error
    }
    stream.use { lockStream ->
      requireRegularDescriptor(descriptor, "setup journal lock")
      lockStream.channel.lock().use {
        // This also reconciles a prior failed sync immediately after the lock
        // namespace was first created.
        syncDirectory()
        operation()
      }
    }
  }

  override fun baseExists(): Boolean = pathExists(base)

  override fun tempExists(): Boolean = pathExists(temp)

  override fun openTempExclusively(): NativeIdentitySetupJournalTempOutput {
    val descriptor =
      Os.open(
        temp.absolutePath,
        OsConstants.O_WRONLY or
          OsConstants.O_CREAT or
          OsConstants.O_EXCL or
          LINUX_O_CLOEXEC or
          LINUX_O_NOFOLLOW,
        OWNER_READ_WRITE,
      )
    val output = try {
      FileOutputStream(descriptor)
    } catch (error: Throwable) {
      try {
        Os.close(descriptor)
      } catch (closeError: Throwable) {
        error.addSuppressed(closeError)
      }
      throw error
    }
    return try {
      requireRegularDescriptor(descriptor, "setup journal staging file")
      AndroidNativeIdentitySetupJournalTempOutput(output)
    } catch (error: Throwable) {
      try {
        output.close()
      } catch (closeError: Throwable) {
        error.addSuppressed(closeError)
      }
      throw error
    }
  }

  override fun openTemp(): InputStream = openRegularForRead(temp, "setup journal staging file")

  override fun openBase(): InputStream = openRegularForRead(base, "setup journal file")

  override fun syncTemp() {
    requireRegularPath(temp, "setup journal staging file")
    val descriptor =
      Os.open(
        temp.absolutePath,
        OsConstants.O_RDONLY or LINUX_O_CLOEXEC or LINUX_O_NOFOLLOW,
        0,
      )
    var failure: Throwable? = null
    try {
      requireRegularDescriptor(descriptor, "setup journal staging file")
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

  override fun renameTempToBase(expectBase: Boolean) {
    requireRegularPath(temp, "setup journal staging file")
    val basePresent = pathExists(base)
    if (basePresent != expectBase) {
      throw NativeIdentitySetupJournalException("setup journal publish precondition changed")
    }
    if (basePresent) requireRegularPath(base, "setup journal file")
    Os.rename(temp.absolutePath, base.absolutePath)
    if (pathExists(temp) || !pathExists(base)) {
      throw NativeIdentitySetupJournalException("setup journal atomic rename failed")
    }
    requireRegularPath(base, "setup journal file")
  }

  override fun deleteTemp() {
    requireRegularPath(temp, "setup journal staging file")
    Os.remove(temp.absolutePath)
  }

  override fun deleteBase() {
    requireRegularPath(base, "setup journal file")
    Os.remove(base.absolutePath)
  }

  override fun syncDirectory() {
    requireDirectory(parent, "setup journal directory")
    val descriptor =
      Os.open(
        parent.absolutePath,
        OsConstants.O_RDONLY or
          LINUX_O_CLOEXEC or
          LINUX_O_NOFOLLOW or
          LINUX_O_DIRECTORY,
        0,
      )
    var failure: Throwable? = null
    try {
      val mode = Os.fstat(descriptor).st_mode
      if (!OsConstants.S_ISDIR(mode)) {
        throw NativeIdentitySetupJournalException("setup journal directory type is invalid")
      }
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

  private fun openRegularForRead(path: File, label: String): InputStream {
    val descriptor =
      Os.open(
        path.absolutePath,
        OsConstants.O_RDONLY or LINUX_O_CLOEXEC or LINUX_O_NOFOLLOW,
        0,
      )
    return try {
      requireRegularDescriptor(descriptor, label)
      FileInputStream(descriptor)
    } catch (error: Throwable) {
      try {
        Os.close(descriptor)
      } catch (closeError: Throwable) {
        error.addSuppressed(closeError)
      }
      throw error
    }
  }

  private fun requireDirectory(path: File, label: String) {
    val mode = lstatModeOrNull(path)
      ?: throw NativeIdentitySetupJournalException("$label is unavailable")
    if (!OsConstants.S_ISDIR(mode)) {
      throw NativeIdentitySetupJournalException("$label type is invalid")
    }
  }

  private fun requireRegularPath(path: File, label: String) {
    val mode = lstatModeOrNull(path)
      ?: throw NativeIdentitySetupJournalException("$label is unavailable")
    if (!OsConstants.S_ISREG(mode)) {
      throw NativeIdentitySetupJournalException("$label type is invalid")
    }
  }

  private fun requireRegularDescriptor(descriptor: java.io.FileDescriptor, label: String) {
    if (!OsConstants.S_ISREG(Os.fstat(descriptor).st_mode)) {
      throw NativeIdentitySetupJournalException("$label type is invalid")
    }
  }

  private fun pathExists(path: File): Boolean = lstatModeOrNull(path) != null

  private fun lstatModeOrNull(path: File): Int? =
    try {
      Os.lstat(path.absolutePath).st_mode
    } catch (error: ErrnoException) {
      if (error.errno == OsConstants.ENOENT) null else throw error
    }

  companion object {
    private val PROCESS_LOCK = Any()
    private const val JOURNAL_FILE_NAME = ".veil-identity-setup-journal.v1"
    private const val TEMP_FILE_NAME = ".veil-identity-setup-journal.v1.new"
    private const val LOCK_FILE_NAME = ".veil-identity-setup-journal.lock"
    private const val OWNER_READ_WRITE = 0x180 // 0600
  }
}

private class AndroidNativeIdentitySetupJournalTempOutput(
  private val output: FileOutputStream,
) : NativeIdentitySetupJournalTempOutput {
  override fun write(bytes: ByteArray) = output.write(bytes)

  override fun flush() = output.flush()

  override fun sync() = output.fd.sync()

  override fun close() = output.close()
}

// Linux UAPI flags are stable across every Android ABI supported by minSdk 24.
// Some android.system.OsConstants Java fields are exposed only on newer APIs.
private const val LINUX_O_DIRECTORY = 0x00010000
private const val LINUX_O_NOFOLLOW = 0x00020000
private const val LINUX_O_CLOEXEC = 0x00080000
