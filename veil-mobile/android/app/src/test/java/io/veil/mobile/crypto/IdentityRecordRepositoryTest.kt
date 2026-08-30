package io.veil.mobile.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityRecordRepositoryTest {
  @Test
  fun missingCurrentRecordReturnsEmptyWithoutWriting() {
    val storage = FakeStorage()

    assertNull(IdentityRecordRepository(storage).load())
    assertEquals(0, storage.writeCalls)
  }

  @Test
  fun currentRecordLoadsAndClearsItsEncodedWorkingCopy() {
    val record = completeRecord()
    val encoded = IdentityVaultRecordCodec.encode(record)
    record.clear()
    val storage = FakeStorage(encoded)

    val loaded = requireNotNull(IdentityRecordRepository(storage).load())

    assertArrayEquals(ByteArray(12) { 3 }, loaded.iv)
    assertArrayEquals(ByteArray(32) { 7 }, loaded.ciphertext)
    assertTrue(requireNotNull(storage.lastReadReference).all { it == 0.toByte() })
    loaded.clear()
  }

  @Test
  fun storeNewPersistsCurrentFormatAndClearsEncodedWorkingCopy() {
    val storage = FakeStorage()
    val repository = IdentityRecordRepository(storage)
    val record = completeRecord()

    repository.storeNew(record)

    val persisted = requireNotNull(storage.encoded)
    val decoded = IdentityVaultRecordCodec.decode(persisted)
    assertArrayEquals(record.iv, decoded.iv)
    assertArrayEquals(record.ciphertext, decoded.ciphertext)
    assertTrue(requireNotNull(storage.lastWriteReference).all { it == 0.toByte() })
    record.clear()
    decoded.clear()
  }

  @Test
  fun existingRecordRejectsReplacementWithoutWriting() {
    val existing = completeRecord()
    val encoded = IdentityVaultRecordCodec.encode(existing)
    existing.clear()
    val storage = FakeStorage(encoded)
    val replacement = completeRecord()

    assertThrows(IdentityVaultException::class.java) {
      IdentityRecordRepository(storage).storeNew(replacement)
    }

    assertEquals(0, storage.writeCalls)
    replacement.clear()
  }

  @Test
  fun failedWriteStillClearsEncodedWorkingCopy() {
    val storage = FakeStorage().apply { failWrite = true }
    val record = completeRecord()

    assertThrows(IdentityVaultException::class.java) {
      IdentityRecordRepository(storage).storeNew(record)
    }

    assertTrue(requireNotNull(storage.lastWriteReference).all { it == 0.toByte() })
    record.clear()
  }

  private class FakeStorage(encoded: ByteArray? = null) : IdentityRecordStorage {
    var encoded: ByteArray? = encoded?.copyOf()
    var failWrite = false
    var writeCalls = 0
    var lastReadReference: ByteArray? = null
    var lastWriteReference: ByteArray? = null

    override fun readOrNull(): ByteArray? = encoded?.copyOf()?.also { lastReadReference = it }

    override fun write(encoded: ByteArray) {
      writeCalls += 1
      lastWriteReference = encoded
      if (failWrite) throw IdentityVaultException("injected commit failure")
      this.encoded = encoded.copyOf()
    }
  }

  private fun completeRecord(): EncryptedIdentityRecord =
    EncryptedIdentityRecord(ByteArray(12) { 3 }, ByteArray(32) { 7 })
}
