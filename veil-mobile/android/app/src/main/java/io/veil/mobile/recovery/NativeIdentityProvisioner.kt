package io.veil.mobile.recovery

import io.veil.mobile.crypto.NativeIdentityVault
import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.security.MessageDigest
import uniffi.veil_ffi.VeilIdentity

internal class RecoveryNotForegroundException : IllegalStateException("recovery is not foreground")

/** Linearizable foreground epoch used around the irreversible durable write. */
internal class RecoveryForegroundGate {
  private var foreground = false
  private var epoch = 0L
  private var irreversibleCommitClaimed = false

  fun markForeground() = synchronized(this) {
    if (!foreground) {
      foreground = true
      epoch += 1
    }
  }

  fun markBackground() = synchronized(this) {
    if (foreground) {
      foreground = false
      epoch += 1
    }
  }

  fun capture(): Long = synchronized(this) {
    if (!foreground) throw RecoveryNotForegroundException()
    epoch
  }

  fun requireCurrent(expected: Long) = synchronized(this) {
    if (!foreground || epoch != expected) throw RecoveryNotForegroundException()
  }

  /**
   * Atomically claims the right to begin the one irreversible disk write.
   * No I/O runs under this monitor: lifecycle revocation is always immediate.
   * Once claimed, the write is non-cancellable and its result is verified even
   * if the UI backgrounds. Secret views are wiped immediately, while the
   * verified transaction still returns the committed terminal result.
   */
  fun claimIrreversibleCommit(expected: Long) = synchronized(this) {
    if (!foreground || epoch != expected) throw RecoveryNotForegroundException()
    check(!irreversibleCommitClaimed) { "identity commit was already claimed" }
    irreversibleCommitClaimed = true
  }

  fun hasIrreversibleCommitClaim(): Boolean = synchronized(this) {
    irreversibleCommitClaimed
  }
}

internal fun interface RecoveryIdentityDeriver {
  /** Returns a new caller-owned public identity-key byte array. */
  fun deriveIdentityKey(mnemonicUtf8: ByteArray): ByteArray
}

internal object UniFfiRecoveryIdentityDeriver : RecoveryIdentityDeriver {
  override fun deriveIdentityKey(mnemonicUtf8: ByteArray): ByteArray {
    val identity = VeilIdentity.fromMnemonicBytes(mnemonicUtf8)
    return try {
      identity.identityKey()
    } finally {
      identity.close()
    }
  }
}

internal fun interface MnemonicProvisioner {
  fun provision(mnemonicUtf8: ByteArray)
}

/**
 * Performs the irreversible native identity transaction.
 *
 * Candidate derivation intentionally occurs before foreground capture. The
 * durable write is then linearized under [RecoveryForegroundGate], and a
 * separately decrypted/read-back identity must match in constant time before
 * success is reported. An already-present identical identity is an idempotent
 * success; a different identity always fails closed.
 */
internal class NativeIdentityProvisioner(
  private val vault: NativeIdentityVaultAccess,
  private val storeNewMnemonicBytes: (ByteArray) -> Unit,
  private val identityDeriver: RecoveryIdentityDeriver,
  private val foregroundGate: RecoveryForegroundGate,
) : MnemonicProvisioner {
  constructor(
    vault: NativeIdentityVault,
    identityDeriver: RecoveryIdentityDeriver = UniFfiRecoveryIdentityDeriver,
    foregroundGate: RecoveryForegroundGate,
  ) : this(vault, vault::storeNewMnemonicBytes, identityDeriver, foregroundGate)

  override fun provision(mnemonicUtf8: ByteArray) {
    require(mnemonicUtf8.isNotEmpty())
    val candidateKey = identityDeriver.deriveIdentityKey(mnemonicUtf8)
    try {
      require(candidateKey.isNotEmpty())
      val epoch = foregroundGate.capture()

      if (vault.hasIdentity()) {
        val matches = existingIdentityMatches(candidateKey)
        foregroundGate.requireCurrent(epoch)
        if (!matches) throw IllegalStateException("a different identity already exists")
        return
      }

      foregroundGate.claimIrreversibleCommit(epoch)
      var writeFailure: Throwable? = null
      try {
        storeNewMnemonicBytes(mnemonicUtf8)
      } catch (error: Throwable) {
        writeFailure = error
      }

      val matches = try {
        vault.hasIdentity() && existingIdentityMatches(candidateKey)
      } catch (readBackFailure: Throwable) {
        writeFailure?.addSuppressed(readBackFailure)
        throw writeFailure ?: readBackFailure
      }
      if (!matches && writeFailure != null) throw writeFailure
      check(matches) { "durable identity read-back does not match the candidate" }
    } finally {
      candidateKey.fill(0)
    }
  }

  private fun existingIdentityMatches(candidateKey: ByteArray): Boolean =
    vault.withMnemonicBytes { persistedMnemonic ->
      val persistedKey = identityDeriver.deriveIdentityKey(persistedMnemonic)
      try {
        MessageDigest.isEqual(candidateKey, persistedKey)
      } finally {
        persistedKey.fill(0)
      }
    }
}

/** Owns and clears the Android-side commit buffers on every terminal path. */
internal class NativeRecoveryCommitRunner(
  private val dictionary: RecoveryWordDictionary,
  private val provisioner: MnemonicProvisioner,
) {
  fun run(flow: RecoveryFlowController, ownedIndices: IntArray) {
    var mnemonic: ByteArray? = null
    try {
      mnemonic = Bip39MnemonicBytes.encode(ownedIndices, dictionary)
      ownedIndices.fill(-1)
      if (!flow.consumeCommitAuthorization()) {
        throw IllegalStateException("recovery authorization was not consumed")
      }
      // Do not insert logging, callbacks, rendering, or bridge work between
      // one-shot authorization and the irreversible provisioner call.
      provisioner.provision(mnemonic)
      flow.markCommitted()
    } finally {
      ownedIndices.fill(-1)
      mnemonic?.fill(0)
    }
  }
}
