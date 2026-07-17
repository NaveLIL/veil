package io.veil.mobile.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class IdentityVaultRecordCodecTest {
  @Test
  fun roundTripPreservesIvAndCiphertext() {
    val source = record()
    val encoded = IdentityVaultRecordCodec.encode(source)

    val decoded = IdentityVaultRecordCodec.decode(encoded)

    assertArrayEquals(source.iv, decoded.iv)
    assertArrayEquals(source.ciphertext, decoded.ciphertext)
    decoded.clear()
    encoded.fill(0)
    source.clear()
  }

  @Test
  fun rejectsWrongMagicVersionAndFlags() {
    assertRejected { it[0] = 0 }
    assertRejected { it[8] = 2 }
    assertRejected { it[9] = 1 }
  }

  @Test
  fun rejectsInvalidLengthsBeforeAllocatingFields() {
    assertRejected {
      it[10] = 0
      it[11] = 11
    }
    assertRejected {
      it[12] = 0x7f
      it[13] = 0xff.toByte()
      it[14] = 0xff.toByte()
      it[15] = 0xff.toByte()
    }
    assertRejected {
      it[12] = 0
      it[13] = 0
      it[14] = 0
      it[15] = 15
    }
  }

  @Test
  fun rejectsTruncationAndTrailingBytes() {
    val source = record()
    val encoded = IdentityVaultRecordCodec.encode(source)
    source.clear()

    assertThrows(IdentityVaultException::class.java) {
      IdentityVaultRecordCodec.decode(encoded.copyOf(encoded.size - 1))
    }
    assertThrows(IdentityVaultException::class.java) {
      IdentityVaultRecordCodec.decode(encoded.copyOf(encoded.size + 1))
    }
    assertThrows(IdentityVaultException::class.java) {
      IdentityVaultRecordCodec.decode(encoded.copyOf(15))
    }
    encoded.fill(0)
  }

  @Test
  fun maximumEncodedSizeIsAnExplicitUpperBound() {
    val maximumCiphertext = ByteArray(8 * 1024) { 0x55 }
    val source = EncryptedIdentityRecord(ByteArray(12) { 0x44 }, maximumCiphertext)
    val encoded = IdentityVaultRecordCodec.encode(source)

    assertEquals(IdentityVaultRecordCodec.MAX_ENCODED_BYTES, encoded.size)
    assertThrows(IdentityVaultException::class.java) {
      IdentityVaultRecordCodec.encode(
        EncryptedIdentityRecord(ByteArray(12), ByteArray(8 * 1024 + 1)),
      )
    }
    encoded.fill(0)
    source.clear()
  }

  private fun assertRejected(mutate: (ByteArray) -> Unit) {
    val source = record()
    val encoded = IdentityVaultRecordCodec.encode(source)
    source.clear()
    mutate(encoded)
    assertThrows(IdentityVaultException::class.java) {
      IdentityVaultRecordCodec.decode(encoded)
    }
    encoded.fill(0)
  }

  private fun record(): EncryptedIdentityRecord =
    EncryptedIdentityRecord(
      iv = ByteArray(12) { index -> (index + 1).toByte() },
      ciphertext = ByteArray(48) { index -> (index + 20).toByte() },
    )
}
