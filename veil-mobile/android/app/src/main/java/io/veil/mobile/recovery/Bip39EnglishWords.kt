package io.veil.mobile.recovery

import android.content.Context
import java.io.ByteArrayOutputStream
import io.veil.mobile.R
import java.security.MessageDigest

/** The exact BIP-39 English index space shared with Rust. */
internal interface RecoveryWordDictionary {
  val size: Int

  fun word(index: Int): String

  fun encodedLength(index: Int): Int

  fun copyEncodedWord(index: Int, destination: ByteArray, offset: Int): Int

  fun findPrefix(prefix: CharArray, length: Int, limit: Int): IntArray
}

/**
 * Loads the pinned, public BIP-39 word list from the APK.
 *
 * The list itself is not secret. Runtime hashing prevents a packaging or merge
 * mistake from silently changing the scalar index mapping used by Rust.
 */
internal class PinnedBip39EnglishWords(context: Context) : RecoveryWordDictionary {
  private val words: Array<String>
  private val utf8: Array<ByteArray>

  init {
    val encoded = context.resources.openRawResource(R.raw.bip39_english).use { input ->
      val output = ByteArrayOutputStream(CANONICAL_BYTES + 1)
      val chunk = ByteArray(1024)
      try {
        while (true) {
          val count = input.read(chunk)
          if (count < 0) break
          check(output.size() + count <= CANONICAL_BYTES + 1) { "BIP-39 word list is too large" }
          output.write(chunk, 0, count)
        }
        output.toByteArray()
      } finally {
        chunk.fill(0)
        output.reset()
      }
    }
    try {
      check(encoded.size == CANONICAL_BYTES) { "BIP-39 word list length is invalid" }
      val canonicalLength = encoded.size
      val digest = MessageDigest.getInstance("SHA-256").run {
        update(encoded, 0, canonicalLength)
        digest()
      }
      try {
        check(MessageDigest.isEqual(digest, EXPECTED_SHA256)) {
          "BIP-39 word list integrity check failed"
        }
      } finally {
        digest.fill(0)
      }

      val parsed = parseAsciiLines(encoded, canonicalLength)
      check(parsed.size == WORD_COUNT) { "BIP-39 word list must contain 2048 words" }
      check(parsed.indices.all { index -> index == 0 || parsed[index - 1] < parsed[index] }) {
        "BIP-39 word list is not strictly sorted"
      }
      words = parsed
      utf8 = Array(parsed.size) { index -> parsed[index].toByteArray(Charsets.US_ASCII) }
    } finally {
      encoded.fill(0)
    }
  }

  override val size: Int
    get() = words.size

  override fun word(index: Int): String = words[checkedIndex(index)]

  override fun encodedLength(index: Int): Int = utf8[checkedIndex(index)].size

  override fun copyEncodedWord(index: Int, destination: ByteArray, offset: Int): Int {
    val source = utf8[checkedIndex(index)]
    require(offset >= 0 && offset <= destination.size - source.size)
    source.copyInto(destination, offset)
    return offset + source.size
  }

  override fun findPrefix(prefix: CharArray, length: Int, limit: Int): IntArray {
    require(length in 0..prefix.size)
    require(limit > 0)
    if (length == 0) return IntArray(0)
    for (index in 0 until length) {
      require(prefix[index] in 'a'..'z')
    }

    val matches = IntArray(limit)
    var count = 0
    for (wordIndex in words.indices) {
      val candidate = words[wordIndex]
      if (candidate.length < length) continue
      var matchesPrefix = true
      for (characterIndex in 0 until length) {
        if (candidate[characterIndex] != prefix[characterIndex]) {
          matchesPrefix = false
          break
        }
      }
      if (matchesPrefix) {
        matches[count++] = wordIndex
        if (count == limit) break
      }
    }
    val result = matches.copyOf(count)
    matches.fill(-1)
    return result
  }

  private fun checkedIndex(index: Int): Int {
    require(index in words.indices) { "word index is outside BIP-39" }
    return index
  }

  private fun parseAsciiLines(encoded: ByteArray, canonicalLength: Int): Array<String> {
    val result = ArrayList<String>(WORD_COUNT)
    var start = 0
    for (cursor in 0 until canonicalLength) {
      val value = encoded[cursor].toInt() and 0xff
      when {
        value == '\n'.code -> {
          val end = if (cursor > start && encoded[cursor - 1] == '\r'.code.toByte()) cursor - 1 else cursor
          if (end > start) result += asciiWord(encoded, start, end)
          start = cursor + 1
        }
        value !in 'a'.code..'z'.code && value != '\r'.code ->
          error("BIP-39 word list contains a non-ASCII character")
      }
    }
    if (start < canonicalLength) result += asciiWord(encoded, start, canonicalLength)
    return result.toTypedArray()
  }

  private fun asciiWord(source: ByteArray, start: Int, end: Int): String {
    require(end > start)
    require(end - start <= MAX_WORD_LENGTH)
    return source.copyOfRange(start, end).toString(Charsets.US_ASCII)
  }

  companion object {
    const val WORD_COUNT = 2048
    const val MAX_WORD_LENGTH = 8
    const val CANONICAL_BYTES = 13_115
    private val EXPECTED_SHA256 =
      byteArrayOf(
        0x18, 0x7d, 0xb0.toByte(), 0x4a, 0x86.toByte(), 0x9d.toByte(), 0xd9.toByte(), 0xbc.toByte(),
        0x7b, 0xe8.toByte(), 0x0d, 0x21, 0xa8.toByte(), 0x64, 0x97.toByte(), 0xd6.toByte(),
        0x92.toByte(), 0xc0.toByte(), 0xdb.toByte(), 0x6a, 0xbd.toByte(), 0x3a, 0xa8.toByte(), 0xcb.toByte(),
        0x6b, 0xe5.toByte(), 0xd6.toByte(), 0x18, 0xff.toByte(), 0x75, 0x7f, 0xae.toByte(),
      )
  }
}

/** Builds canonical single-space ASCII without constructing a mnemonic String. */
internal object Bip39MnemonicBytes {
  fun encode(indices: IntArray, dictionary: RecoveryWordDictionary): ByteArray {
    require(indices.isNotEmpty())
    var length = indices.size - 1
    for (index in indices) {
      require(index in 0 until dictionary.size)
      length = Math.addExact(length, dictionary.encodedLength(index))
    }
    require(length <= MAX_MNEMONIC_BYTES)

    val result = ByteArray(length)
    var offset = 0
    for (position in indices.indices) {
      if (position != 0) result[offset++] = ' '.code.toByte()
      offset = dictionary.copyEncodedWord(indices[position], result, offset)
    }
    check(offset == result.size)
    return result
  }

  private const val MAX_MNEMONIC_BYTES = 24 * (PinnedBip39EnglishWords.MAX_WORD_LENGTH + 1)
}
