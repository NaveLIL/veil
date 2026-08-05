package io.veil.mobile.recovery

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Bip39PinnedWordListTest {
  @Test
  fun rawDictionaryIsTheExactRustCanonicalIndexSpace() {
    val encoded = Files.readAllBytes(projectFile("src/main/res/raw/bip39_english.txt"))
    val expectedDigest = hex("187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae")
    val actualDigest = MessageDigest.getInstance("SHA-256").digest(encoded)
    try {
      assertEquals(13_115, encoded.size)
      assertFalse("canonical word list must not end in LF", encoded.last() == '\n'.code.toByte())
      assertArrayEquals(expectedDigest, actualDigest)
      val words = encoded.toString(Charsets.US_ASCII).split('\n')
      assertEquals(2048, words.size)
      assertEquals("abandon", words.first())
      assertEquals("zoo", words.last())
      assertTrue(words.zipWithNext().all { (left, right) -> left < right })
    } finally {
      expectedDigest.fill(0)
      actualDigest.fill(0)
      encoded.fill(0)
    }
  }

  @Test
  fun mnemonicEncodingUsesSingleSpacesAndNoTrailingDelimiter() {
    val words = Files.readAllBytes(projectFile("src/main/res/raw/bip39_english.txt"))
      .toString(Charsets.US_ASCII)
      .split('\n')
    val dictionary = ListDictionary(words)

    val encoded = Bip39MnemonicBytes.encode(intArrayOf(0, 3, 2047), dictionary)

    assertArrayEquals("abandon about zoo".toByteArray(Charsets.US_ASCII), encoded)
    encoded.fill(0)
  }

  @Test
  fun phraseGridSourceNeverBuildsAnImmutableSelectedPhrase() {
    val grid = Files.readAllBytes(
      projectFile("src/main/java/io/veil/mobile/recovery/RecoveryPhraseGridView.kt"),
    ).toString(Charsets.UTF_8)
    val activity = Files.readAllBytes(
      projectFile("src/main/java/io/veil/mobile/recovery/RecoveryActivity.kt"),
    ).toString(Charsets.UTF_8)

    assertFalse(grid.contains("joinToString"))
    assertFalse(grid.contains("StringBuilder"))
    assertFalse(grid.contains("words.word"))
    assertFalse(activity.contains("\${words.word"))
    assertFalse(activity.contains("joinToString"))
  }

  @Test
  fun recoveryProductionSourceHasNoImeClipboardLoggingOrPhraseStringPath() {
    val recoveryDirectory = projectFile("src/main/java/io/veil/mobile/recovery/RecoveryActivity.kt").parent
    val combined = StringBuilder()
    Files.list(recoveryDirectory).use { files ->
      files
        .filter { path -> path.fileName.toString().endsWith(".kt") }
        .sorted()
        .forEach { path -> combined.append(Files.readAllBytes(path).toString(Charsets.UTF_8)) }
    }
    val source = combined.toString()

    assertFalse(source.contains("EditText"))
    assertFalse(source.contains("Clipboard"))
    assertFalse(source.contains("ClipData"))
    assertFalse(source.contains("android.util.Log"))
    assertFalse(source.contains("joinToString"))
    assertFalse(source.contains("mnemonic: String"))
    val intentExtraNames = Regex("putExtra\\(\\s*(EXTRA_[A-Z_]+)")
      .findAll(source)
      .map { match -> match.groupValues[1] }
      .toList()
    assertEquals(8, Regex("putExtra\\(").findAll(source).count())
    assertEquals(8, intentExtraNames.size)
    assertEquals(
      setOf(
        "EXTRA_MODE",
        "EXTRA_LEASE_ID",
        "EXTRA_ATTEMPT_ID",
        "EXTRA_PROCESS_INCARNATION_ID",
        "EXTRA_RESULT_LEASE_ID",
        "EXTRA_RESULT_ATTEMPT_ID",
        "EXTRA_RESULT_PROCESS_INCARNATION_ID",
        "EXTRA_RESULT_OUTCOME",
      ),
      intentExtraNames.toSet(),
    )
    assertTrue(source.contains("RecoveryPrivateInputView"))
    assertFalse(source.contains("setText(inputChars"))
    assertTrue(source.contains("setContentCaptureEnabled(false)"))
    assertTrue(source.contains("IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS"))
  }

  private fun projectFile(relative: String): Path {
    val candidates = listOf(
      Paths.get(relative),
      Paths.get("app").resolve(relative),
      Paths.get("veil-mobile/android/app").resolve(relative),
    )
    return candidates.firstOrNull(Files::isRegularFile)
      ?: error("cannot locate Android project file $relative from ${Paths.get("").toAbsolutePath()}")
  }

  private fun hex(value: String): ByteArray =
    ByteArray(value.length / 2) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }

  private class ListDictionary(words: List<String>) : RecoveryWordDictionary {
    private val values = words.toTypedArray()
    private val bytes = Array(values.size) { values[it].toByteArray(Charsets.US_ASCII) }

    override val size: Int = values.size

    override fun word(index: Int): String = values[index]

    override fun encodedLength(index: Int): Int = bytes[index].size

    override fun copyEncodedWord(index: Int, destination: ByteArray, offset: Int): Int {
      bytes[index].copyInto(destination, offset)
      return offset + bytes[index].size
    }

    override fun findPrefix(prefix: CharArray, length: Int, limit: Int): IntArray = IntArray(0)
  }
}
