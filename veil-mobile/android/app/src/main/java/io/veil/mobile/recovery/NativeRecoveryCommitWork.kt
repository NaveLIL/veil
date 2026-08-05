package io.veil.mobile.recovery

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-owned recovery transaction.
 *
 * Once constructed, this object is the only owner of [ownedIndices] and the
 * native [flow]. [close] is idempotent and overwrites/releases both even when
 * executor submission, provisioning, or Activity recreation fails.
 */
internal class NativeRecoveryCommitWork(
  private val flow: RecoveryFlowController,
  private val ownedIndices: IntArray,
  private val runner: NativeRecoveryCommitRunner,
) : NativeIdentitySetupCoordinator.CommitWork {
  private val closed = AtomicBoolean(false)

  override fun run(): NativeIdentitySetupCoordinator.CommitOutcome {
    check(!closed.get()) { "identity commit work is closed" }
    runner.run(flow, ownedIndices)
    return NativeIdentitySetupCoordinator.CommitOutcome.COMMITTED
  }

  override fun close() {
    if (!closed.compareAndSet(false, true)) return
    ownedIndices.fill(-1)
    try {
      flow.close()
    } catch (_: Throwable) {
      // The native authorization was already consumed or cancelled. Its
      // destructor remains a fallback; Android buffers are already cleared.
    }
  }
}
