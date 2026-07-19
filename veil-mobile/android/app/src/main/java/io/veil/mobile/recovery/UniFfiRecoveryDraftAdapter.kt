package io.veil.mobile.recovery

import uniffi.veil_ffi.VeilRecoveryDraft

/**
 * The only Android file coupled to generated UniFFI names and unsigned scalar
 * types. No word, phrase, or other secret string crosses this adapter.
 */
internal object UniFfiRecoveryDraftFactory : RecoveryDraftFactory {
  override fun create(mode: RecoveryMode): RecoveryDraft =
    UniFfiRecoveryDraftAdapter(
      mode = mode,
      native =
        if (mode == RecoveryMode.CREATE) {
          VeilRecoveryDraft.newCreate()
        } else {
          VeilRecoveryDraft.newRestore()
        },
    )
}

private class UniFfiRecoveryDraftAdapter(
  override val mode: RecoveryMode,
  private val native: VeilRecoveryDraft,
) : RecoveryDraft {
  override fun wordCount(): Int = native.wordCount().toInt()

  override fun wordIndex(position: Int): Int =
    native.wordIndex(position.asUByte("position")).toInt()

  override fun setImportWordIndex(position: Int, index: Int) =
    native.setImportWordIndex(
      position.asUByte("position"),
      index.asUShort("word index"),
    )

  override fun validateImport(): Boolean = native.validateImport()

  override fun challengeCount(): Int = native.challengeCount().toInt()

  override fun challengePosition(slot: Int): Int =
    native.challengePosition(slot.asUByte("challenge slot")).toInt()

  override fun challengeChoiceCount(): Int = native.challengeChoiceCount().toInt()

  override fun challengeChoiceWordIndex(slot: Int, choice: Int): Int =
    native.challengeChoiceWordIndex(
      slot.asUByte("challenge slot"),
      choice.asUByte("challenge choice"),
    ).toInt()

  override fun confirmChallenge(slot: Int, chosen: Int): Boolean =
    native.confirmChallenge(
      slot.asUByte("challenge slot"),
      chosen.asUShort("word index"),
    )

  override fun isCommitAuthorized(): Boolean = native.isCommitAuthorized()

  override fun consumeCommitAuthorization(): Boolean = native.consumeCommitAuthorization()

  override fun cancel() = native.cancel()

  override fun close() = native.close()

  private fun Int.asUByte(label: String): UByte {
    require(this in 0..UByte.MAX_VALUE.toInt()) { "$label is outside u8" }
    return toUByte()
  }

  private fun Int.asUShort(label: String): UShort {
    require(this in 0..UShort.MAX_VALUE.toInt()) { "$label is outside u16" }
    return toUShort()
  }
}
