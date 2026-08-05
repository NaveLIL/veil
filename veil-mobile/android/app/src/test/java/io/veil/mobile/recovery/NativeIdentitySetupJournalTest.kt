package io.veil.mobile.recovery

import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeIdentitySetupJournalTest {
  @Test
  fun strictCodecRoundTripsEveryReachableShape() {
    val createFiles = FakeJournalFiles()
    val create = journal(createFiles, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = create.begin(NativeIdentitySetupJournalMode.CREATE)
    val active = create.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
    val committing = create.transition(active, NativeIdentitySetupJournalPhase.COMMITTING)
    val committed =
      create.transition(
        committing,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.COMMITTED,
      )

    val restoreFiles = FakeJournalFiles()
    val restore = journal(restoreFiles, PROCESS_TWO, ATTEMPT_TWO)
    val restorePrepared = restore.begin(NativeIdentitySetupJournalMode.RESTORE)
    val restoreActive =
      restore.transition(restorePrepared, NativeIdentitySetupJournalPhase.ACTIVE)
    val cancelled =
      restore.transition(
        restoreActive,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.USER_CANCELLED,
      )

    val interruptedFiles = FakeJournalFiles()
    val interruptedJournal = journal(interruptedFiles, PROCESS_THREE, ATTEMPT_THREE)
    val interruptedPrepared =
      interruptedJournal.begin(NativeIdentitySetupJournalMode.CREATE)
    val interrupted =
      interruptedJournal.transition(
        interruptedPrepared,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.INTERRUPTED,
      )

    listOf(
      prepared,
      active,
      committing,
      committed,
      restorePrepared,
      restoreActive,
      cancelled,
      interrupted,
    ).forEach { record ->
      val encoded = NativeIdentitySetupJournalCodec.encode(record)
      assertEquals(NativeIdentitySetupJournalCodec.MAX_ENCODED_BYTES, encoded.size)
      assertEquals(record, NativeIdentitySetupJournalCodec.decode(encoded))
      encoded.fill(0)
    }
  }

  @Test
  fun transitionsAreLinearBoundedAndCarryRandomAttemptAndProcessIds() {
    val files = FakeJournalFiles()
    val firstProcess = journal(files, PROCESS_ONE, ATTEMPT_ONE)

    val prepared = firstProcess.begin(NativeIdentitySetupJournalMode.CREATE)
    assertEquals(ATTEMPT_ONE, prepared.attemptId)
    assertEquals(PROCESS_ONE, prepared.processIncarnationId)
    assertNotEquals(prepared.attemptId, prepared.processIncarnationId)
    assertEquals(1, prepared.revision)
    assertEquals(NativeIdentitySetupJournalPhase.PREPARED, prepared.phase)
    assertNull(prepared.outcome)

    val active = firstProcess.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
    assertEquals(2, active.revision)
    assertEquals(NativeIdentitySetupJournalPhase.ACTIVE, active.phase)

    val committing =
      firstProcess.transition(active, NativeIdentitySetupJournalPhase.COMMITTING)
    assertEquals(3, committing.revision)
    assertEquals(NativeIdentitySetupJournalPhase.COMMITTING, committing.phase)

    val recreatedProcess = journal(files, PROCESS_TWO)
    assertEquals(committing, recreatedProcess.readOrNull())
    val terminal =
      recreatedProcess.transition(
        committing,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.COMMITTED,
      )
    assertEquals(4, terminal.revision)
    assertEquals(PROCESS_TWO, terminal.processIncarnationId)
    assertEquals(ATTEMPT_ONE, terminal.attemptId)
    assertEquals(NativeIdentitySetupJournalOutcome.COMMITTED, terminal.outcome)
    assertEquals(terminal, recreatedProcess.readOrNull())

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      recreatedProcess.transition(
        terminal,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.INTERRUPTED,
      )
    }
  }

  @Test
  fun invalidOrSkippedTransitionsNeverMutateTheDurableRecord() {
    val files = FakeJournalFiles()
    val journal = journal(files, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = journal.begin(NativeIdentitySetupJournalMode.RESTORE)
    val original = files.baseCopy()

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.transition(prepared, NativeIdentitySetupJournalPhase.COMMITTING)
    }
    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.transition(
        prepared,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.COMMITTED,
      )
    }
    assertArrayEquals(original, files.baseCopy())

    val active = journal.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.transition(
        active,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.COMMITTED,
      )
    }
    assertEquals(active, journal.readOrNull())
  }

  @Test
  fun beginNeverOverwritesAndOnlyExactTerminalCanBeCleared() {
    val files = FakeJournalFiles()
    val journal = journal(files, PROCESS_ONE, ATTEMPT_ONE, ATTEMPT_TWO)
    val prepared = journal.begin(NativeIdentitySetupJournalMode.CREATE)

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.begin(NativeIdentitySetupJournalMode.RESTORE)
    }
    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.clearTerminal(prepared)
    }
    assertEquals(prepared, journal.readOrNull())

    val active = journal.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
    val terminal =
      journal.transition(
        active,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.USER_CANCELLED,
      )
    journal.clearTerminal(terminal)
    assertNull(journal.readOrNull())

    val second = journal.begin(NativeIdentitySetupJournalMode.RESTORE)
    assertEquals(ATTEMPT_TWO, second.attemptId)
    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.clearTerminal(terminal)
    }
    assertEquals(second, journal.readOrNull())
  }

  @Test
  fun everyStrictPrefixIsTruncatedAndExtraBytesAreTrailing() {
    val encoded = encodedPrepared()
    for (length in 0 until encoded.size) {
      assertThrows(
        "prefix length $length must fail closed",
        NativeIdentitySetupJournalException::class.java,
      ) {
        NativeIdentitySetupJournalCodec.decode(encoded.copyOf(length))
      }
    }

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      NativeIdentitySetupJournalCodec.decode(encoded + byteArrayOf(0))
    }
  }

  @Test
  fun unknownVersionFlagsEnumsRevisionAndReservedBytesFailClosed() {
    val encoded = encodedPrepared()
    val mutations =
      listOf(
        NativeIdentitySetupJournalCodec.VERSION_OFFSET to 2,
        NativeIdentitySetupJournalCodec.FLAGS_OFFSET to 1,
        NativeIdentitySetupJournalCodec.MODE_OFFSET to 0xff,
        NativeIdentitySetupJournalCodec.PHASE_OFFSET to 0xff,
        NativeIdentitySetupJournalCodec.OUTCOME_OFFSET to 0xff,
        NativeIdentitySetupJournalCodec.REVISION_OFFSET to 0,
        NativeIdentitySetupJournalCodec.RESERVED_OFFSET to 1,
      )
    mutations.forEach { (offset, value) ->
      val invalid = encoded.copyOf()
      invalid[offset] = value.toByte()
      assertThrows(
        "wire offset $offset must be closed",
        NativeIdentitySetupJournalException::class.java,
      ) {
        NativeIdentitySetupJournalCodec.decode(invalid)
      }
    }
  }

  @Test
  fun checksumValidButUnreachablePhaseOutcomeShapeFailsClosed() {
    val invalid = encodedPrepared()
    invalid[NativeIdentitySetupJournalCodec.PHASE_OFFSET] =
      NativeIdentitySetupJournalPhase.TERMINAL.wireValue.toByte()
    invalid[NativeIdentitySetupJournalCodec.OUTCOME_OFFSET] =
      NativeIdentitySetupJournalOutcome.COMMITTED.wireValue.toByte()
    invalid[NativeIdentitySetupJournalCodec.REVISION_OFFSET] = 2
    resign(invalid)

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      NativeIdentitySetupJournalCodec.decode(invalid)
    }
  }

  @Test
  fun checksumDetectsCorruptionInsideOtherwiseValidRandomIdentifiers() {
    val encoded = encodedPrepared()
    encoded[NativeIdentitySetupJournalCodec.ATTEMPT_ID_OFFSET + 15] =
      (encoded[NativeIdentitySetupJournalCodec.ATTEMPT_ID_OFFSET + 15].toInt() xor 1).toByte()

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      NativeIdentitySetupJournalCodec.decode(encoded)
    }
  }

  @Test
  fun randomIdentifierSourceIsBoundedAndCannotReuseTheProcessIdentifier() {
    val files = FakeJournalFiles()
    val repeated = MutableList(9) { PROCESS_ONE }
    val journal = journal(files, *repeated.toTypedArray())

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.begin(NativeIdentitySetupJournalMode.CREATE)
    }
    assertNull(files.baseCopy())
    assertNull(files.tempCopy())

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal(FakeJournalFiles(), UUID(0, 0))
    }
  }

  @Test
  fun recordSchemaAndEncodedBytesCannotCarrySecretOrDiagnosticCanaries() {
    val files = FakeJournalFiles()
    val journal = journal(files, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = journal.begin(NativeIdentitySetupJournalMode.CREATE)
    val encoded = requireNotNull(files.baseCopy())

    val instanceFields =
      NativeIdentitySetupJournalRecord::class.java.declaredFields
        .filterNot { Modifier.isStatic(it.modifiers) }
        .map { it.type }
    assertFalse(instanceFields.contains(String::class.java))
    assertFalse(instanceFields.any { it == ByteArray::class.java })
    assertEquals(6, instanceFields.size)

    val canaries =
      listOf(
        "abandon abandon abandon about",
        "seed-canary-material",
        "private-key-canary",
        "identity-key-canary",
        "https://node-canary.example",
        "VEIL-PASS-CANARY-0001",
        "diagnostic stack trace canary",
      )
    canaries.forEach { canary ->
      assertFalse(
        "journal bytes must not contain $canary",
        encoded.containsSubsequence(canary.toByteArray(StandardCharsets.UTF_8)),
      )
    }
    assertFalse(prepared.toString().contains(ATTEMPT_ONE.toString()))
    assertFalse(prepared.toString().contains(PROCESS_ONE.toString()))
  }

  @Test
  fun preRenameIoFaultsThrowAndPreserveTheOldAuthoritativeRecord() {
    val failurePoints =
      listOf(
        FailurePoint.OPEN_TEMP,
        FailurePoint.WRITE,
        FailurePoint.FLUSH,
        FailurePoint.TEMP_SYNC,
        FailurePoint.TEMP_READ,
        FailurePoint.RENAME,
      )
    failurePoints.forEach { point ->
      val files = FakeJournalFiles()
      val journal = journal(files, PROCESS_ONE, ATTEMPT_ONE)
      val prepared = journal.begin(NativeIdentitySetupJournalMode.CREATE)
      val original = requireNotNull(files.baseCopy())
      files.failNext(point)

      assertThrows("fault $point must fail closed", NativeIdentitySetupJournalException::class.java) {
        journal.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
      }

      assertArrayEquals("fault $point replaced base", original, files.baseCopy())
      assertNull("fault $point left a live-process staging file", files.tempCopy())
      assertEquals(prepared, journal.readOrNull())
    }
  }

  @Test
  fun preRenameDirectorySyncFaultPreservesBaseAndCleansStaging() {
    val files = FakeJournalFiles()
    val journal = journal(files, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = journal.begin(NativeIdentitySetupJournalMode.CREATE)
    val original = requireNotNull(files.baseCopy())
    files.failDirectorySyncAfterCalls(1)

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
    }

    assertArrayEquals(original, files.baseCopy())
    assertNull(files.tempCopy())
  }

  @Test
  fun postRenameSyncFailureIsAmbiguousButReopenObservesTheNewState() {
    val files = FakeJournalFiles()
    val journal = journal(files, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = journal.begin(NativeIdentitySetupJournalMode.CREATE)
    files.failDirectorySyncAfterCalls(2)

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
    }

    assertNull(files.tempCopy())
    val reopened = journal(files, PROCESS_TWO)
    val recovered = requireNotNull(reopened.readOrNull())
    assertEquals(NativeIdentitySetupJournalPhase.ACTIVE, recovered.phase)
    assertEquals(2, recovered.revision)
  }

  @Test
  fun syncedStagedSuccessorIsPromotedAfterSimulatedProcessDeath() {
    val sourceFiles = FakeJournalFiles()
    val source = journal(sourceFiles, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = source.begin(NativeIdentitySetupJournalMode.RESTORE)
    val preparedBytes = requireNotNull(sourceFiles.baseCopy())
    val active = source.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
    val activeBytes = requireNotNull(sourceFiles.baseCopy())

    val crashedFiles = FakeJournalFiles().apply {
      install(base = preparedBytes, temp = activeBytes)
    }
    val reopened = journal(crashedFiles, PROCESS_TWO)

    assertEquals(active, reopened.readOrNull())
    assertEquals(1, crashedFiles.recoveryTempSyncCalls())
    assertArrayEquals(activeBytes, crashedFiles.baseCopy())
    assertNull(crashedFiles.tempCopy())
  }

  @Test
  fun syncedInitialPreparedStageIsPromotedInsteadOfSilentlyCleared() {
    val sourceFiles = FakeJournalFiles()
    val source = journal(sourceFiles, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = source.begin(NativeIdentitySetupJournalMode.CREATE)
    val preparedBytes = requireNotNull(sourceFiles.baseCopy())

    val crashedFiles = FakeJournalFiles().apply { install(base = null, temp = preparedBytes) }
    val reopened = journal(crashedFiles, PROCESS_TWO)

    assertEquals(prepared, reopened.readOrNull())
    assertEquals(1, crashedFiles.recoveryTempSyncCalls())
    assertArrayEquals(preparedBytes, crashedFiles.baseCopy())
    assertNull(crashedFiles.tempCopy())
  }

  @Test
  fun stagedRecoveryFsyncFailurePreservesBothOldAuthorityAndPendingStage() {
    val sourceFiles = FakeJournalFiles()
    val source = journal(sourceFiles, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = source.begin(NativeIdentitySetupJournalMode.CREATE)
    val preparedBytes = requireNotNull(sourceFiles.baseCopy())
    val active = source.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
    val activeBytes = NativeIdentitySetupJournalCodec.encode(active)
    val crashedFiles = FakeJournalFiles().apply {
      install(base = preparedBytes, temp = activeBytes)
      failNext(FailurePoint.TEMP_SYNC)
    }

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal(crashedFiles, PROCESS_TWO).readOrNull()
    }
    assertArrayEquals(preparedBytes, crashedFiles.baseCopy())
    assertArrayEquals(activeBytes, crashedFiles.tempCopy())
  }

  @Test
  fun corruptOrSkippedStagingNeverOverwritesTheLastValidBase() {
    val sourceFiles = FakeJournalFiles()
    val source = journal(sourceFiles, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = source.begin(NativeIdentitySetupJournalMode.CREATE)
    val preparedBytes = requireNotNull(sourceFiles.baseCopy())
    val active = source.transition(prepared, NativeIdentitySetupJournalPhase.ACTIVE)
    val committing = source.transition(active, NativeIdentitySetupJournalPhase.COMMITTING)
    val skippedBytes = NativeIdentitySetupJournalCodec.encode(committing)

    val skippedFiles = FakeJournalFiles().apply {
      install(base = preparedBytes, temp = skippedBytes)
    }
    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal(skippedFiles, PROCESS_TWO).readOrNull()
    }
    assertArrayEquals(preparedBytes, skippedFiles.baseCopy())
    assertArrayEquals(skippedBytes, skippedFiles.tempCopy())

    val corrupt = skippedBytes.copyOfRange(0, skippedBytes.size - 1)
    val corruptFiles = FakeJournalFiles().apply {
      install(base = preparedBytes, temp = corrupt)
    }
    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal(corruptFiles, PROCESS_THREE).readOrNull()
    }
    assertArrayEquals(preparedBytes, corruptFiles.baseCopy())
    assertArrayEquals(corrupt, corruptFiles.tempCopy())
  }

  @Test
  fun corruptBaseFailsClosedAndCannotBeOverwrittenByBegin() {
    val corrupt = ByteArray(NativeIdentitySetupJournalCodec.MAX_ENCODED_BYTES) { 0x5a }
    val files = FakeJournalFiles().apply { install(base = corrupt, temp = null) }
    val journal = journal(files, PROCESS_ONE, ATTEMPT_ONE)

    assertThrows(NativeIdentitySetupJournalException::class.java) { journal.readOrNull() }
    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.begin(NativeIdentitySetupJournalMode.CREATE)
    }
    assertArrayEquals(corrupt, files.baseCopy())
  }

  @Test
  fun terminalClearIoFaultIsReportedAndNeverMasqueradesAsSuccess() {
    val files = FakeJournalFiles()
    val journal = journal(files, PROCESS_ONE, ATTEMPT_ONE)
    val prepared = journal.begin(NativeIdentitySetupJournalMode.CREATE)
    val terminal =
      journal.transition(
        prepared,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.INTERRUPTED,
      )
    files.failNext(FailurePoint.DELETE_BASE)

    assertThrows(NativeIdentitySetupJournalException::class.java) {
      journal.clearTerminal(terminal)
    }
    assertEquals(terminal, journal.readOrNull())
  }

  private fun encodedPrepared(): ByteArray {
    val files = FakeJournalFiles()
    val journal = journal(files, PROCESS_ONE, ATTEMPT_ONE)
    return NativeIdentitySetupJournalCodec.encode(
      journal.begin(NativeIdentitySetupJournalMode.CREATE),
    )
  }

  private fun resign(encoded: ByteArray) {
    val digest = MessageDigest.getInstance("SHA-256").apply {
      update(encoded, 0, NativeIdentitySetupJournalCodec.HASH_OFFSET)
    }.digest()
    digest.copyInto(encoded, destinationOffset = NativeIdentitySetupJournalCodec.HASH_OFFSET)
    digest.fill(0)
  }

  private fun journal(
    files: FakeJournalFiles,
    vararg ids: UUID,
  ): NativeIdentitySetupJournal =
    NativeIdentitySetupJournal(
      directory = File("unused-test-no-backup-directory"),
      idSource = SequenceIdSource(*ids),
      files = files,
    )

  private class SequenceIdSource(vararg ids: UUID) : NativeIdentitySetupJournalIdSource {
    private val remaining = ArrayDeque(ids.toList())

    override fun nextId(): UUID =
      if (remaining.isEmpty()) {
        throw IllegalStateException("test UUID source exhausted")
      } else {
        remaining.removeFirst()
      }
  }

  private enum class FailurePoint {
    LOCK,
    OPEN_TEMP,
    WRITE,
    FLUSH,
    TEMP_SYNC,
    TEMP_READ,
    BASE_READ,
    RENAME,
    DELETE_TEMP,
    DELETE_BASE,
  }

  private class FakeJournalFiles : NativeIdentitySetupJournalFileOps {
    private val monitor = Any()
    private var base: ByteArray? = null
    private var temp: ByteArray? = null
    private var nextFailure: FailurePoint? = null
    private var directorySyncCalls = 0
    private var directorySyncFailureCall: Int? = null
    private var recoveryTempSyncCalls = 0

    override fun <T> withExclusiveLock(operation: () -> T): T = synchronized(monitor) {
      hit(FailurePoint.LOCK)
      operation()
    }

    override fun baseExists(): Boolean = base != null

    override fun tempExists(): Boolean = temp != null

    override fun openTempExclusively(): NativeIdentitySetupJournalTempOutput {
      hit(FailurePoint.OPEN_TEMP)
      if (temp != null) throw IOException("test temp already exists")
      temp = ByteArray(0)
      return object : NativeIdentitySetupJournalTempOutput {
        private var closed = false

        override fun write(bytes: ByteArray) {
          check(!closed)
          hit(FailurePoint.WRITE)
          temp = bytes.copyOf()
        }

        override fun flush() {
          check(!closed)
          hit(FailurePoint.FLUSH)
        }

        override fun sync() {
          check(!closed)
          hit(FailurePoint.TEMP_SYNC)
        }

        override fun close() {
          closed = true
        }
      }
    }

    override fun openTemp(): InputStream {
      hit(FailurePoint.TEMP_READ)
      return ByteArrayInputStream(requireNotNull(temp).copyOf())
    }

    override fun openBase(): InputStream {
      hit(FailurePoint.BASE_READ)
      return ByteArrayInputStream(requireNotNull(base).copyOf())
    }

    override fun syncTemp() {
      hit(FailurePoint.TEMP_SYNC)
      check(temp != null)
      recoveryTempSyncCalls += 1
    }

    override fun renameTempToBase(expectBase: Boolean) {
      hit(FailurePoint.RENAME)
      check((base != null) == expectBase)
      base = requireNotNull(temp).copyOf()
      temp = null
    }

    override fun deleteTemp() {
      hit(FailurePoint.DELETE_TEMP)
      check(temp != null)
      temp = null
    }

    override fun deleteBase() {
      hit(FailurePoint.DELETE_BASE)
      check(base != null)
      base = null
    }

    override fun syncDirectory() {
      directorySyncCalls += 1
      if (directorySyncFailureCall == directorySyncCalls) {
        directorySyncFailureCall = null
        throw IOException("injected directory sync failure")
      }
    }

    fun failNext(point: FailurePoint) {
      check(nextFailure == null)
      nextFailure = point
    }

    /** Fails after [additionalSuccessfulCalls] more successful sync calls. */
    fun failDirectorySyncAfterCalls(additionalSuccessfulCalls: Int) {
      directorySyncFailureCall = directorySyncCalls + additionalSuccessfulCalls + 1
    }

    fun install(base: ByteArray?, temp: ByteArray?) {
      this.base = base?.copyOf()
      this.temp = temp?.copyOf()
    }

    fun baseCopy(): ByteArray? = base?.copyOf()

    fun recoveryTempSyncCalls(): Int = recoveryTempSyncCalls

    fun tempCopy(): ByteArray? = temp?.copyOf()

    private fun hit(point: FailurePoint) {
      if (nextFailure == point) {
        nextFailure = null
        throw IOException("injected $point failure")
      }
    }
  }

  companion object {
    private val PROCESS_ONE = UUID.fromString("10000000-0000-4000-8000-000000000001")
    private val PROCESS_TWO = UUID.fromString("20000000-0000-4000-8000-000000000002")
    private val PROCESS_THREE = UUID.fromString("30000000-0000-4000-8000-000000000003")
    private val ATTEMPT_ONE = UUID.fromString("a0000000-0000-4000-8000-000000000001")
    private val ATTEMPT_TWO = UUID.fromString("b0000000-0000-4000-8000-000000000002")
    private val ATTEMPT_THREE = UUID.fromString("c0000000-0000-4000-8000-000000000003")
  }
}

private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean {
  if (needle.isEmpty() || needle.size > size) return false
  for (start in 0..size - needle.size) {
    var matches = true
    for (index in needle.indices) {
      if (this[start + index] != needle[index]) {
        matches = false
        break
      }
    }
    if (matches) return true
  }
  return false
}
