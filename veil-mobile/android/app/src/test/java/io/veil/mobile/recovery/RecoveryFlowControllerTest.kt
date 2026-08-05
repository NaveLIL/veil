package io.veil.mobile.recovery

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RecoveryFlowControllerTest {
  @Test
  fun createRequiresEveryNativeChallengeBeforeOneShotCommit() {
    val events = mutableListOf<String>()
    val draft = FakeDraft(RecoveryMode.CREATE, events)
    val flow = RecoveryFlowController(draft, TestDictionary())

    assertEquals(RecoveryStage.CREATE_REVIEW, flow.stage)
    assertArrayEquals(IntArray(12) { it }, IntArray(12) { flow.wordIndex(it) })
    flow.continueFromCreateReview()
    assertFalse(flow.chooseChallengeWord(100))
    assertEquals(RecoveryIssue.WRONG_CHALLENGE_WORD, flow.issue)
    assertTrue(flow.chooseChallengeWord(0))
    assertTrue(flow.chooseChallengeWord(2))
    assertEquals(RecoveryStage.READY_TO_COMMIT, flow.stage)

    val owned = flow.copyIndicesForCommit()
    assertTrue(flow.consumeCommitAuthorization())
    assertFalse(flow.consumeCommitAuthorization())
    flow.markCommitted()
    flow.close()

    assertArrayEquals(IntArray(12) { it }, owned)
    assertTrue((0 until 12).all { flow.wordIndex(it) == -1 })
    assertEquals(listOf("consume", "close"), events.takeLast(2))
    assertFalse(events.contains("cancel"))
    owned.fill(-1)
  }

  @Test
  fun restoreUsesFixedInputBuffersAndNativeValidation() {
    val draft = FakeDraft(RecoveryMode.RESTORE)
    val flow = RecoveryFlowController(draft, TestDictionary())

    flow.appendInput('a')
    flow.appendInput('b')
    assertArrayEquals(charArrayOf('a', 'b'), flow.inputCopy())
    assertArrayEquals(intArrayOf(0, 1, 2, 3), flow.suggestions())

    for (position in 0 until 12) {
      assertTrue(flow.chooseImportWord(position))
    }
    assertEquals(RecoveryStage.READY_TO_COMMIT, flow.stage)
    flow.close()
    assertTrue((0 until 12).all { flow.wordIndex(it) == -1 })
    assertTrue(draft.cancelled)
  }

  @Test
  fun restoreBackErasesInputThenPreviousWordAndCreateChallengeCancels() {
    val restore = RecoveryFlowController(FakeDraft(RecoveryMode.RESTORE), TestDictionary())
    restore.appendInput('a')
    assertEquals(RecoveryBackResult.UPDATED, restore.handleBack())
    restore.chooseImportWord(0)
    assertEquals(RecoveryBackResult.UPDATED, restore.handleBack())
    assertEquals(0, restore.restorePosition())
    assertEquals(-1, restore.wordIndex(0))
    assertEquals(RecoveryBackResult.CANCEL, restore.handleBack())
    restore.close()

    val create = RecoveryFlowController(FakeDraft(RecoveryMode.CREATE), TestDictionary())
    create.continueFromCreateReview()
    assertEquals(RecoveryBackResult.CANCEL, create.handleBack())
    create.close()
  }

  @Test
  fun restoreBackAfterInvalidFinalWordClearsOnlyThatWord() {
    val restore = RecoveryFlowController(FakeDraft(RecoveryMode.RESTORE), TestDictionary())
    for (position in 0 until 11) {
      assertTrue(restore.chooseImportWord(position))
    }
    assertFalse(restore.chooseImportWord(42))
    assertEquals(RecoveryIssue.INVALID_PHRASE, restore.issue)
    assertEquals(11, restore.restorePosition())

    assertEquals(RecoveryBackResult.UPDATED, restore.handleBack())
    assertEquals(11, restore.restorePosition())
    assertEquals(-1, restore.wordIndex(11))
    assertEquals(10, restore.wordIndex(10))
    assertEquals(RecoveryIssue.NONE, restore.issue)

    assertEquals(RecoveryBackResult.UPDATED, restore.handleBack())
    assertEquals(10, restore.restorePosition())
    assertEquals(-1, restore.wordIndex(10))
    restore.close()
  }

  @Test
  fun committingBlocksBackAndClosedDraftCannotBeReused() {
    val flow = RecoveryFlowController(FakeDraft(RecoveryMode.CREATE), TestDictionary())
    flow.continueFromCreateReview()
    flow.chooseChallengeWord(0)
    flow.chooseChallengeWord(2)
    val owned = flow.copyIndicesForCommit()

    assertEquals(RecoveryBackResult.BLOCKED, flow.handleBack())
    flow.close()
    assertThrows(IllegalStateException::class.java) { flow.consumeCommitAuthorization() }
    owned.fill(-1)
  }

  private class FakeDraft(
    override val mode: RecoveryMode,
    private val events: MutableList<String> = mutableListOf(),
  ) : RecoveryDraft {
    private val words = IntArray(12) { if (mode == RecoveryMode.CREATE) it else -1 }
    private val confirmed = BooleanArray(2)
    var cancelled = false
    private var consumed = false

    override fun wordCount(): Int = words.size

    override fun wordIndex(position: Int): Int = words[position]

    override fun setImportWordIndex(position: Int, index: Int) {
      words[position] = index
    }

    override fun validateImport(): Boolean = words.indices.all { words[it] == it }

    override fun challengeCount(): Int = 2

    override fun challengePosition(slot: Int): Int = slot * 2

    override fun challengeChoiceCount(): Int = 3

    override fun challengeChoiceWordIndex(slot: Int, choice: Int): Int =
      if (choice == 0) challengePosition(slot) else 100 + slot * 3 + choice

    override fun confirmChallenge(slot: Int, chosen: Int): Boolean =
      (chosen == challengePosition(slot)).also { if (it) confirmed[slot] = true }

    override fun isCommitAuthorized(): Boolean =
      if (mode == RecoveryMode.CREATE) confirmed.all { it } else validateImport()

    override fun consumeCommitAuthorization(): Boolean {
      events += "consume"
      if (consumed) return false
      consumed = true
      val authorized = isCommitAuthorized()
      words.fill(-1)
      return authorized
    }

    override fun cancel() {
      events += "cancel"
      cancelled = true
      words.fill(-1)
    }

    override fun close() {
      events += "close"
    }
  }

  private class TestDictionary : RecoveryWordDictionary {
    private val values = Array(2048) { index -> when (index) {
      0 -> "abandon"
      1 -> "ability"
      2 -> "able"
      3 -> "about"
      else -> "word"
    } }

    override val size: Int = values.size

    override fun word(index: Int): String = values[index]

    override fun encodedLength(index: Int): Int = values[index].length

    override fun copyEncodedWord(index: Int, destination: ByteArray, offset: Int): Int {
      val encoded = values[index].toByteArray(Charsets.US_ASCII)
      return try {
        encoded.copyInto(destination, offset)
        offset + encoded.size
      } finally {
        encoded.fill(0)
      }
    }

    override fun findPrefix(prefix: CharArray, length: Int, limit: Int): IntArray =
      intArrayOf(0, 1, 2, 3).copyOf(limit.coerceAtMost(4))
  }
}
