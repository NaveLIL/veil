package io.veil.mobile.recovery

internal enum class RecoveryMode {
  CREATE,
  RESTORE;

  fun toBridge(): String = when (this) {
    CREATE -> "create"
    RESTORE -> "restore"
  }

  companion object {
    fun fromBridge(value: String): RecoveryMode? = when (value) {
      "create" -> CREATE
      "restore" -> RESTORE
      else -> null
    }
  }
}

internal enum class RecoveryStage {
  CREATE_REVIEW,
  CREATE_CHALLENGE,
  RESTORE_ENTRY,
  READY_TO_COMMIT,
  COMMITTING,
  COMMITTED,
  CLOSED,
}

/** Scalar-only Android boundary around the native Rust recovery draft. */
internal interface RecoveryDraft : AutoCloseable {
  val mode: RecoveryMode

  fun wordCount(): Int

  fun wordIndex(position: Int): Int

  fun setImportWordIndex(position: Int, index: Int)

  fun validateImport(): Boolean

  fun challengeCount(): Int

  fun challengePosition(slot: Int): Int

  fun challengeChoiceCount(): Int

  fun challengeChoiceWordIndex(slot: Int, choice: Int): Int

  fun confirmChallenge(slot: Int, chosen: Int): Boolean

  fun isCommitAuthorized(): Boolean

  /** One-shot; Rust terminally clears the draft regardless of the result. */
  fun consumeCommitAuthorization(): Boolean

  /** Terminally clears a draft that was not consumed. */
  fun cancel()
}

internal fun interface RecoveryDraftFactory {
  fun create(mode: RecoveryMode): RecoveryDraft
}

internal enum class RecoveryIssue {
  NONE,
  WRONG_CHALLENGE_WORD,
  INVALID_PHRASE,
  SETUP_FAILED,
}

internal enum class RecoveryBackResult {
  UPDATED,
  CANCEL,
  BLOCKED,
}

/**
 * Owns every secret scalar held by the Android UI. Arrays are fixed-size and
 * mutable so they can be deterministically overwritten on every terminal path.
 */
internal class RecoveryFlowController(
  private val draft: RecoveryDraft,
  private val dictionary: RecoveryWordDictionary,
) : AutoCloseable {
  private val indices: IntArray
  private val input = CharArray(PinnedBip39EnglishWords.MAX_WORD_LENGTH)
  private var inputLength = 0
  private var restorePosition = 0
  private var challengeSlot = 0
  private var draftConsumed = false

  var stage: RecoveryStage
    private set

  var issue: RecoveryIssue = RecoveryIssue.NONE
    private set

  init {
    val count = draft.wordCount()
    require(count in ALLOWED_WORD_COUNTS)
    indices = IntArray(count) { UNSET_WORD }
    stage = when (draft.mode) {
      RecoveryMode.CREATE -> {
        for (position in indices.indices) {
          indices[position] = checkedWordIndex(draft.wordIndex(position))
        }
        require(draft.challengeCount() in 1..indices.size)
        require(draft.challengeChoiceCount() in 2..MAX_CHALLENGE_CHOICES)
        RecoveryStage.CREATE_REVIEW
      }
      RecoveryMode.RESTORE -> RecoveryStage.RESTORE_ENTRY
    }
  }

  val mode: RecoveryMode
    get() = draft.mode

  fun wordCount(): Int = synchronized(this) { indices.size }

  fun wordIndex(position: Int): Int = synchronized(this) {
    require(position in indices.indices)
    indices[position]
  }

  fun restorePosition(): Int = synchronized(this) { restorePosition }

  fun inputCopy(): CharArray = synchronized(this) { input.copyOf(inputLength) }

  fun suggestions(limit: Int = DEFAULT_SUGGESTION_LIMIT): IntArray = synchronized(this) {
    ensureStage(RecoveryStage.RESTORE_ENTRY)
    dictionary.findPrefix(input, inputLength, limit)
  }

  fun appendInput(letter: Char): Boolean = synchronized(this) {
    ensureStage(RecoveryStage.RESTORE_ENTRY)
    require(letter in 'a'..'z')
    if (inputLength == input.size) return@synchronized false
    input[inputLength++] = letter
    issue = RecoveryIssue.NONE
    true
  }

  fun eraseInput(): Boolean = synchronized(this) {
    ensureStage(RecoveryStage.RESTORE_ENTRY)
    if (inputLength == 0) return@synchronized false
    input[--inputLength] = '\u0000'
    issue = RecoveryIssue.NONE
    true
  }

  fun chooseImportWord(index: Int): Boolean = synchronized(this) {
    ensureStage(RecoveryStage.RESTORE_ENTRY)
    val checked = checkedWordIndex(index)
    draft.setImportWordIndex(restorePosition, checked)
    indices[restorePosition] = checked
    clearInput()

    if (restorePosition < indices.lastIndex) {
      restorePosition += 1
      issue = RecoveryIssue.NONE
      return@synchronized true
    }

    if (!draft.validateImport() || !draft.isCommitAuthorized()) {
      issue = RecoveryIssue.INVALID_PHRASE
      return@synchronized false
    }
    stage = RecoveryStage.READY_TO_COMMIT
    issue = RecoveryIssue.NONE
    true
  }

  fun continueFromCreateReview() = synchronized(this) {
    ensureStage(RecoveryStage.CREATE_REVIEW)
    challengeSlot = 0
    issue = RecoveryIssue.NONE
    stage = RecoveryStage.CREATE_CHALLENGE
  }

  fun challengePosition(): Int = synchronized(this) {
    ensureStage(RecoveryStage.CREATE_CHALLENGE)
    val position = draft.challengePosition(challengeSlot)
    require(position in indices.indices)
    position
  }

  fun challengeChoices(): IntArray = synchronized(this) {
    ensureStage(RecoveryStage.CREATE_CHALLENGE)
    IntArray(draft.challengeChoiceCount()) { choice ->
      checkedWordIndex(draft.challengeChoiceWordIndex(challengeSlot, choice))
    }
  }

  fun chooseChallengeWord(index: Int): Boolean = synchronized(this) {
    ensureStage(RecoveryStage.CREATE_CHALLENGE)
    val accepted = draft.confirmChallenge(challengeSlot, checkedWordIndex(index))
    if (!accepted) {
      issue = RecoveryIssue.WRONG_CHALLENGE_WORD
      return@synchronized false
    }

    challengeSlot += 1
    issue = RecoveryIssue.NONE
    if (challengeSlot == draft.challengeCount()) {
      check(draft.isCommitAuthorized()) { "native recovery authorization is incomplete" }
      stage = RecoveryStage.READY_TO_COMMIT
    }
    true
  }

  /** Copies indices once and moves the flow into the non-cancellable commit UI. */
  fun copyIndicesForCommit(): IntArray = synchronized(this) {
    ensureStage(RecoveryStage.READY_TO_COMMIT)
    check(indices.all { it != UNSET_WORD })
    stage = RecoveryStage.COMMITTING
    indices.copyOf()
  }

  /** Must be called immediately before provisioning, after mnemonic bytes exist. */
  fun consumeCommitAuthorization(): Boolean = synchronized(this) {
    ensureStage(RecoveryStage.COMMITTING)
    if (draftConsumed) return@synchronized false
    draftConsumed = true
    draft.consumeCommitAuthorization()
  }

  fun markCommitted() = synchronized(this) {
    ensureStage(RecoveryStage.COMMITTING)
    stage = RecoveryStage.COMMITTED
    wipeUiBuffers()
  }

  fun markSetupFailed() = synchronized(this) {
    if (stage == RecoveryStage.CLOSED || stage == RecoveryStage.COMMITTED) return@synchronized
    issue = RecoveryIssue.SETUP_FAILED
    closeLocked()
  }

  fun handleBack(): RecoveryBackResult = synchronized(this) {
    when (stage) {
      RecoveryStage.COMMITTING -> RecoveryBackResult.BLOCKED
      RecoveryStage.RESTORE_ENTRY -> when {
        inputLength > 0 -> {
          eraseInput()
          RecoveryBackResult.UPDATED
        }
        indices[restorePosition] != UNSET_WORD -> {
          indices[restorePosition] = UNSET_WORD
          issue = RecoveryIssue.NONE
          RecoveryBackResult.UPDATED
        }
        restorePosition > 0 -> {
          restorePosition -= 1
          indices[restorePosition] = UNSET_WORD
          issue = RecoveryIssue.NONE
          RecoveryBackResult.UPDATED
        }
        else -> RecoveryBackResult.CANCEL
      }
      // Native challenge confirmation is intentionally monotonic. Leaving the
      // challenge cancels the whole draft instead of trying to rewind Rust.
      RecoveryStage.CREATE_CHALLENGE -> RecoveryBackResult.CANCEL
      RecoveryStage.CREATE_REVIEW,
      RecoveryStage.READY_TO_COMMIT -> RecoveryBackResult.CANCEL
      RecoveryStage.COMMITTED,
      RecoveryStage.CLOSED -> RecoveryBackResult.BLOCKED
    }
  }

  override fun close() = synchronized(this) { closeLocked() }

  private fun closeLocked() {
    if (stage == RecoveryStage.CLOSED) return
    if (!draftConsumed) {
      try {
        draft.cancel()
      } catch (_: Throwable) {
        // The UI boundary is terminal and must still wipe its own state.
      }
    }
    try {
      draft.close()
    } catch (_: Throwable) {
      // UniFFI cleanup is best effort after the native draft was cancelled.
    }
    wipeUiBuffers()
    stage = RecoveryStage.CLOSED
  }

  private fun clearInput() {
    input.fill('\u0000')
    inputLength = 0
  }

  private fun wipeUiBuffers() {
    indices.fill(UNSET_WORD)
    clearInput()
    restorePosition = 0
    challengeSlot = 0
  }

  private fun checkedWordIndex(index: Int): Int {
    require(index in 0 until dictionary.size)
    return index
  }

  private fun ensureStage(expected: RecoveryStage) {
    check(stage == expected) { "recovery flow is not in $expected" }
  }

  companion object {
    private const val UNSET_WORD = -1
    private const val DEFAULT_SUGGESTION_LIMIT = 4
    private const val MAX_CHALLENGE_CHOICES = 8
    private val ALLOWED_WORD_COUNTS = setOf(12, 15, 18, 21, 24)
  }
}
