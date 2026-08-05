package io.veil.mobile.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Physical-filesystem regression tests for Android's immutable identity publication protocol. */
@RunWith(AndroidJUnit4::class)
class AndroidDurableIdentityFileOpsInstrumentedTest {
  @Test
  fun directoryPublicationSurvivesReadBackAndRefusesOverwrite() {
    withProbeBase { base ->
      val storage = WriteOnceIdentityRecordStorage(AndroidDurableIdentityFileOps(base))

      storage.write(RECORD)

      assertTrue(base.isDirectory)
      assertArrayEquals(RECORD, storage.readOrNull())
      assertThrows(IdentityVaultException::class.java) { storage.write(OTHER_RECORD) }
      assertArrayEquals(RECORD, storage.readOrNull())
      assertFalse(File(base.parentFile, base.name + ".new").exists())
    }
  }

  @Test
  fun legacyRegularFileAtTheSameBasePathRemainsReadableAndImmutable() {
    withProbeBase { base ->
      writeAndSync(base, LEGACY_RECORD)
      val storage = WriteOnceIdentityRecordStorage(AndroidDurableIdentityFileOps(base))

      assertArrayEquals(LEGACY_RECORD, storage.readOrNull())
      assertThrows(IdentityVaultException::class.java) { storage.write(OTHER_RECORD) }
      assertTrue(base.isFile)
      assertArrayEquals(LEGACY_RECORD, base.readBytes())
    }
  }

  @Test
  fun publishRaceCannotReplaceACompetingNonEmptyDirectory() {
    withProbeBase { base ->
      val files = AndroidDurableIdentityFileOps(base)
      files.openTempExclusively().use { output ->
        output.write(RECORD)
        output.flush()
        output.sync()
      }
      files.openTemp().use { input -> assertArrayEquals(RECORD, input.readBytes()) }
      files.syncTempDirectory()
      files.syncDirectory()

      assertTrue(base.mkdir())
      writeAndSync(File(base, PUBLISHED_RECORD_FILE_NAME), COMPETING_RECORD)

      assertThrows(Exception::class.java) { files.publishTempToBaseIfAbsent() }
      assertArrayEquals(COMPETING_RECORD, files.openBase().use { it.readBytes() })
      assertTrue(File(base.parentFile, base.name + ".new").isDirectory)
      files.deleteTemp()
    }
  }

  private fun withProbeBase(operation: (File) -> Unit) {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val base = File(context.noBackupFilesDir, ".veil-storage-probe-${UUID.randomUUID()}")
    val staging = File(base.parentFile, base.name + ".new")
    check(!base.exists() && !staging.exists())
    try {
      operation(base)
    } finally {
      deleteExactProbePath(staging)
      deleteExactProbePath(base)
    }
  }

  private fun writeAndSync(file: File, bytes: ByteArray) {
    FileOutputStream(file).use { output ->
      output.write(bytes)
      output.flush()
      output.fd.sync()
    }
  }

  private fun deleteExactProbePath(path: File) {
    if (!path.exists()) return
    if (path.isDirectory) {
      val children = path.listFiles() ?: error("cannot list probe directory ${path.name}")
      check(children.size <= 1)
      children.singleOrNull()?.let { child ->
        check(child.name == PUBLISHED_RECORD_FILE_NAME && child.isFile)
        check(child.delete())
      }
    } else {
      check(path.isFile)
    }
    check(path.delete())
  }

  companion object {
    private const val PUBLISHED_RECORD_FILE_NAME = "record.bin"
    private val RECORD = byteArrayOf(0x56, 0x45, 0x49, 0x4c, 0x01)
    private val OTHER_RECORD = byteArrayOf(0x56, 0x45, 0x49, 0x4c, 0x02)
    private val LEGACY_RECORD = byteArrayOf(0x56, 0x45, 0x49, 0x4c, 0x03)
    private val COMPETING_RECORD = byteArrayOf(0x56, 0x45, 0x49, 0x4c, 0x04)
  }
}
