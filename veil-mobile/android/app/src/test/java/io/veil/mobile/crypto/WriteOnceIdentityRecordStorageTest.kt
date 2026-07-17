package io.veil.mobile.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class WriteOnceIdentityRecordStorageTest {
  @Test
  fun successfulWriteSyncsFileRenamesSyncsDirectoryAndReadsBack() {
    val files = FakeDurableIdentityFileOps()
    val storage = WriteOnceIdentityRecordStorage(files)

    storage.write(RECORD)

    assertArrayEquals(RECORD, files.base)
    assertNull(files.temp)
    assertEquals(
      listOf(
        "open-temp",
        "write",
        "flush",
        "file-sync",
        "close",
        "open-temp-read",
        "publish",
        "dir-sync",
        "delete-temp",
        "dir-sync",
        "open-base",
      ),
      files.events,
    )
  }

  @Test
  fun existingIdentityIsImmutableAndNeverOpenedForOverwrite() {
    val original = byteArrayOf(9, 8, 7)
    val files = FakeDurableIdentityFileOps(base = original)

    assertThrows(IdentityVaultException::class.java) {
      WriteOnceIdentityRecordStorage(files).write(RECORD)
    }

    assertArrayEquals(original, files.base)
    assertFalse(files.events.contains("open-temp"))
    assertFalse(files.events.contains("publish"))
  }

  @Test
  fun fileSyncFailureRemovesTempAndNeverCreatesBase() {
    val files = FakeDurableIdentityFileOps().apply { failure = Failure.FILE_SYNC }

    assertThrows(IdentityVaultException::class.java) {
      WriteOnceIdentityRecordStorage(files).write(RECORD)
    }

    assertNull(files.base)
    assertNull(files.temp)
    assertTrue(files.events.containsAll(listOf("file-sync", "close", "delete-temp", "dir-sync")))
  }

  @Test
  fun temporaryReadBackMismatchIsRejectedBeforePublish() {
    val files = FakeDurableIdentityFileOps().apply { failure = Failure.TEMP_READBACK_MISMATCH }

    assertThrows(IdentityVaultException::class.java) {
      WriteOnceIdentityRecordStorage(files).write(RECORD)
    }

    assertNull(files.base)
    assertNull(files.temp)
    assertTrue(files.events.contains("delete-temp"))
    assertFalse(files.events.contains("publish"))
  }

  @Test
  fun failureBeforePublishRemovesTempAndNeverCreatesBase() {
    val files = FakeDurableIdentityFileOps().apply { failure = Failure.PUBLISH_BEFORE }

    assertThrows(IdentityVaultException::class.java) {
      WriteOnceIdentityRecordStorage(files).write(RECORD)
    }

    assertNull(files.base)
    assertNull(files.temp)
    assertTrue(files.events.contains("delete-temp"))
  }

  @Test
  fun reportedPublishFailureNeverDeletesBaseAndCanBeVerifiedLater() {
    val files = FakeDurableIdentityFileOps().apply { failure = Failure.PUBLISH_AFTER }
    val storage = WriteOnceIdentityRecordStorage(files)

    assertThrows(IdentityVaultException::class.java) { storage.write(RECORD) }
    assertArrayEquals(RECORD, files.base)
    assertNull(files.temp)

    files.failure = Failure.NONE
    assertArrayEquals(RECORD, storage.readOrNull())
  }

  @Test
  fun atomicNoReplaceRacePreservesCompetingBase() {
    val files = FakeDurableIdentityFileOps().apply { failure = Failure.PUBLISH_RACE }

    assertThrows(IdentityVaultException::class.java) {
      WriteOnceIdentityRecordStorage(files).write(RECORD)
    }

    assertArrayEquals(COMPETING_RECORD, files.base)
    assertNull(files.temp)
  }

  @Test
  fun directorySyncFailureKeepsBaseAndRequiresSuccessfulReadRetry() {
    val files = FakeDurableIdentityFileOps().apply { failure = Failure.DIRECTORY_SYNC }
    val storage = WriteOnceIdentityRecordStorage(files)

    assertThrows(IdentityVaultException::class.java) { storage.write(RECORD) }
    assertArrayEquals(RECORD, files.base)

    files.failure = Failure.NONE
    assertArrayEquals(RECORD, storage.readOrNull())
  }

  @Test
  fun baseReadBackExceptionAndMismatchAreReportedWithoutDeletingBase() {
    for (failure in listOf(Failure.OPEN_BASE, Failure.BASE_READBACK_MISMATCH)) {
      val files = FakeDurableIdentityFileOps().apply { this.failure = failure }
      val storage = WriteOnceIdentityRecordStorage(files)

      assertThrows(IdentityVaultException::class.java) { storage.write(RECORD) }
      assertArrayEquals(RECORD, files.base)
      assertNull(files.temp)

      files.failure = Failure.NONE
      assertArrayEquals(RECORD, storage.readOrNull())
    }
  }

  @Test
  fun crashResidueWithoutBaseIsRemovedBeforeReportingEmpty() {
    val files = FakeDurableIdentityFileOps(temp = byteArrayOf(4, 5, 6))

    assertNull(WriteOnceIdentityRecordStorage(files).readOrNull())

    assertNull(files.temp)
    assertEquals(listOf("delete-temp", "dir-sync"), files.events)
  }

  @Test
  fun crashResidueBesideBaseIsRemovedWithoutChangingIdentity() {
    val files = FakeDurableIdentityFileOps(base = RECORD, temp = byteArrayOf(4, 5, 6))

    val loaded = WriteOnceIdentityRecordStorage(files).readOrNull()

    assertArrayEquals(RECORD, loaded)
    assertArrayEquals(RECORD, files.base)
    assertNull(files.temp)
    assertTrue(files.events.contains("delete-temp"))
  }

  @Test
  fun closeFailureRemovesTempAndLeavesBaseAbsent() {
    val files = FakeDurableIdentityFileOps().apply { failure = Failure.CLOSE }

    assertThrows(IdentityVaultException::class.java) {
      WriteOnceIdentityRecordStorage(files).write(RECORD)
    }

    assertNull(files.base)
    assertNull(files.temp)
  }

  @Test
  fun oversizedBaseIsRejectedAfterDirectorySync() {
    val files =
      FakeDurableIdentityFileOps(
        base = ByteArray(IdentityVaultRecordCodec.MAX_ENCODED_BYTES + 1),
      )

    assertThrows(IdentityVaultException::class.java) {
      WriteOnceIdentityRecordStorage(files).readOrNull()
    }
    assertEquals("dir-sync", files.events.first())
  }

  companion object {
    private val RECORD = byteArrayOf(1, 2, 3, 4, 5)
    private val COMPETING_RECORD = byteArrayOf(9, 9, 9)
  }
}

internal enum class Failure {
  NONE,
  WRITE,
  FLUSH,
  FILE_SYNC,
  CLOSE,
  OPEN_TEMP,
  TEMP_READBACK_MISMATCH,
  PUBLISH_BEFORE,
  PUBLISH_AFTER,
  PUBLISH_RACE,
  DIRECTORY_SYNC,
  OPEN_BASE,
  BASE_READBACK_MISMATCH,
  DELETE_TEMP,
}

internal class FakeDurableIdentityFileOps(
  base: ByteArray? = null,
  temp: ByteArray? = null,
) : DurableIdentityFileOps {
  var base: ByteArray? = base?.copyOf()
  var temp: ByteArray? = temp?.copyOf()
  var failure = Failure.NONE
  val events = mutableListOf<String>()

  override fun baseExists(): Boolean = base != null

  override fun tempExists(): Boolean = temp != null

  override fun deleteTemp() {
    events += "delete-temp"
    if (failure == Failure.DELETE_TEMP) throw IllegalStateException("injected delete failure")
    temp = null
  }

  override fun openTempExclusively(): DurableIdentityTempOutput {
    events += "open-temp"
    check(temp == null) { "temp already exists" }
    val buffer = ByteArrayOutputStream()
    return object : DurableIdentityTempOutput {
      override fun write(bytes: ByteArray) {
        events += "write"
        if (failure == Failure.WRITE) throw IllegalStateException("injected write failure")
        buffer.write(bytes)
        temp = buffer.toByteArray()
      }

      override fun flush() {
        events += "flush"
        if (failure == Failure.FLUSH) throw IllegalStateException("injected flush failure")
      }

      override fun sync() {
        events += "file-sync"
        if (failure == Failure.FILE_SYNC) throw IllegalStateException("injected file sync failure")
      }

      override fun close() {
        events += "close"
        if (failure == Failure.CLOSE) throw IllegalStateException("injected close failure")
      }
    }
  }

  override fun openTemp(): InputStream {
    events += "open-temp-read"
    if (failure == Failure.OPEN_TEMP) throw IllegalStateException("injected temp read failure")
    val result = checkNotNull(temp).copyOf()
    if (failure == Failure.TEMP_READBACK_MISMATCH && result.isNotEmpty()) {
      result[result.lastIndex] = (result.last() + 1).toByte()
    }
    return ByteArrayInputStream(result)
  }

  override fun publishTempToBaseIfAbsent() {
    events += "publish"
    check(base == null) { "refusing overwrite" }
    if (failure == Failure.PUBLISH_BEFORE) {
      throw IllegalStateException("injected pre-publish failure")
    }
    if (failure == Failure.PUBLISH_RACE) {
      base = byteArrayOf(9, 9, 9)
      throw IllegalStateException("injected no-replace race")
    }
    base = checkNotNull(temp).copyOf()
    if (failure == Failure.PUBLISH_AFTER) {
      throw IllegalStateException("injected post-publish failure")
    }
  }

  override fun syncDirectory() {
    events += "dir-sync"
    if (failure == Failure.DIRECTORY_SYNC) {
      throw IllegalStateException("injected directory sync failure")
    }
  }

  override fun openBase(): InputStream {
    events += "open-base"
    if (failure == Failure.OPEN_BASE) throw IllegalStateException("injected read-back failure")
    val result = checkNotNull(base).copyOf()
    if (failure == Failure.BASE_READBACK_MISMATCH && result.isNotEmpty()) {
      result[result.lastIndex] = (result.last() + 1).toByte()
    }
    return ByteArrayInputStream(result)
  }
}
