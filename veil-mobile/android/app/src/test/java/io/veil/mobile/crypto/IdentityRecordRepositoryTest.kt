package io.veil.mobile.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityRecordRepositoryTest {
  @Test
  fun migrationCommitsAtomicRecordBeforeClearingLegacy() {
    val events = mutableListOf<String>()
    val storage = FakeStorage(events = events)
    val legacy = FakeLegacy(completeRecord(), events)
    val repository = IdentityRecordRepository(storage, legacy)

    val loaded = requireNotNull(repository.load())

    assertEquals(listOf("write", "clear"), events)
    assertEquals(1, legacy.clearCalls)
    assertTrue(requireNotNull(storage.lastWriteReference).all { it == 0.toByte() })
    val persisted = requireNotNull(storage.encoded)
    val decoded = IdentityVaultRecordCodec.decode(persisted)
    assertArrayEquals(loaded.iv, decoded.iv)
    assertArrayEquals(loaded.ciphertext, decoded.ciphertext)
    loaded.clear()
    decoded.clear()
  }

  @Test
  fun failedAtomicCommitNeverClearsLegacy() {
    val events = mutableListOf<String>()
    val storage = FakeStorage(events = events).apply { failWrite = true }
    val legacyRecord = completeRecord()
    val legacy = FakeLegacy(legacyRecord, events)

    assertThrows(IdentityVaultException::class.java) {
      IdentityRecordRepository(storage, legacy).load()
    }

    assertEquals(listOf("write"), events)
    assertEquals(0, legacy.clearCalls)
    assertFalse(legacy.recordWasClearedBeforeRead)
    assertTrue(legacyRecord.iv.all { it == 0.toByte() })
    assertTrue(legacyRecord.ciphertext.all { it == 0.toByte() })
    assertTrue(requireNotNull(storage.lastWriteReference).all { it == 0.toByte() })
  }

  @Test
  fun everyReportedDurabilityFailureKeepsLegacy() {
    val failures =
      listOf(
        Failure.FILE_SYNC,
        Failure.TEMP_READBACK_MISMATCH,
        Failure.TEMP_DIRECTORY_SYNC,
        Failure.STAGING_PARENT_SYNC,
        Failure.PUBLISH_BEFORE,
        Failure.DIRECTORY_SYNC,
        Failure.OPEN_BASE,
        Failure.BASE_READBACK_MISMATCH,
      )

    for (failure in failures) {
      val files = FakeDurableIdentityFileOps().apply { this.failure = failure }
      val legacy = FakeLegacy(completeRecord())
      val repository =
        IdentityRecordRepository(WriteOnceIdentityRecordStorage(files), legacy)

      assertThrows(IdentityVaultException::class.java) { repository.load() }
      assertEquals("legacy cleared after $failure", 0, legacy.clearCalls)
      assertTrue("legacy disappeared after $failure", legacy.present)
    }
  }

  @Test
  fun laterDurabilityVerificationCanAuthoritativelyFinishMigration() {
    val files = FakeDurableIdentityFileOps().apply { failure = Failure.DIRECTORY_SYNC }
    val legacy = FakeLegacy(completeRecord())
    val repository = IdentityRecordRepository(WriteOnceIdentityRecordStorage(files), legacy)

    assertThrows(IdentityVaultException::class.java) { repository.load() }
    assertEquals(0, legacy.clearCalls)
    assertNotNull(files.base)

    files.failure = Failure.NONE
    val recovered = requireNotNull(repository.load())
    assertEquals(1, legacy.readCalls)
    assertEquals(1, legacy.clearCalls)
    assertFalse(legacy.present)
    recovered.clear()
  }

  @Test
  fun partialLegacyRecordIsRejectedWithoutWriting() {
    val storage = FakeStorage()
    val legacy = FakeLegacy(state = LegacyIdentityState.Partial)

    assertThrows(IdentityVaultException::class.java) {
      IdentityRecordRepository(storage, legacy).load()
    }

    assertEquals(0, storage.writeCalls)
    assertEquals(0, legacy.clearCalls)
  }

  @Test
  fun existingAtomicRecordIsAuthoritativeOverPartialLegacy() {
    val atomicRecord = completeRecord()
    val encoded = IdentityVaultRecordCodec.encode(atomicRecord)
    atomicRecord.clear()
    val storage = FakeStorage(encoded = encoded)
    val legacy = FakeLegacy(state = LegacyIdentityState.Partial)

    val loaded = requireNotNull(IdentityRecordRepository(storage, legacy).load())

    assertEquals(0, legacy.readCalls)
    assertEquals(1, legacy.clearCalls)
    loaded.clear()
  }

  @Test
  fun cleanupFailureDoesNotFailLoadAndIsRetriedFromAtomicRecord() {
    val storage = FakeStorage()
    val legacy = FakeLegacy(completeRecord()).apply { clearSucceeds = false }
    val repository = IdentityRecordRepository(storage, legacy)

    val migrated = requireNotNull(repository.load())
    migrated.clear()
    assertNotNull(storage.encoded)
    assertEquals(1, legacy.readCalls)
    assertEquals(1, legacy.clearCalls)

    legacy.clearSucceeds = true
    val recovered = requireNotNull(repository.load())
    assertEquals(1, legacy.readCalls)
    assertEquals(2, legacy.clearCalls)
    recovered.clear()
  }

  private class FakeStorage(
    encoded: ByteArray? = null,
    private val events: MutableList<String> = mutableListOf(),
  ) : IdentityRecordStorage {
    var encoded: ByteArray? = encoded?.copyOf()
    var failWrite = false
    var writeCalls = 0
    var lastWriteReference: ByteArray? = null

    override fun readOrNull(): ByteArray? = encoded?.copyOf()

    override fun write(encoded: ByteArray) {
      writeCalls += 1
      events += "write"
      lastWriteReference = encoded
      if (failWrite) throw IdentityVaultException("injected commit failure")
      this.encoded = encoded.copyOf()
    }
  }

  private class FakeLegacy(
    private val state: LegacyIdentityState,
    private val events: MutableList<String> = mutableListOf(),
  ) : LegacyIdentitySource {
    constructor(record: EncryptedIdentityRecord, events: MutableList<String> = mutableListOf()) :
      this(LegacyIdentityState.Complete(record), events)

    var clearSucceeds = true
    var present = state !is LegacyIdentityState.Empty
    var readCalls = 0
    var clearCalls = 0
    var recordWasClearedBeforeRead = false

    override fun hasAny(): Boolean = present

    override fun read(): LegacyIdentityState {
      readCalls += 1
      if (!present) return LegacyIdentityState.Empty
      if (state is LegacyIdentityState.Complete) {
        recordWasClearedBeforeRead = state.record.iv.all { it == 0.toByte() }
      }
      return state
    }

    override fun clear(): Boolean {
      clearCalls += 1
      events += "clear"
      if (clearSucceeds) present = false
      return clearSucceeds
    }
  }

  private fun completeRecord(): EncryptedIdentityRecord =
    EncryptedIdentityRecord(ByteArray(12) { 3 }, ByteArray(32) { 7 })
}
