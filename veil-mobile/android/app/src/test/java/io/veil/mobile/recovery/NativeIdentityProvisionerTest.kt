package io.veil.mobile.recovery

import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeIdentityProvisionerTest {
  @Test
  fun verifiesCandidateThenWritesThenReadsBackBeforeSuccess() {
    val events = mutableListOf<String>()
    val vault = FakeVault(events = events)
    val deriver = RecordingDeriver(events)
    val gate = RecoveryForegroundGate().apply { markForeground() }
    val provisioner = NativeIdentityProvisioner(
      vault = vault,
      storeNewMnemonicBytes = { bytes ->
        events += "write"
        vault.persist(bytes)
      },
      identityDeriver = deriver,
      foregroundGate = gate,
    )

    provisioner.provision(CANDIDATE.copyOf())

    assertEquals(listOf("derive", "has", "write", "has", "read", "derive"), events)
    assertTrue(deriver.returnedKeys.all { key -> key.all { it == 0.toByte() } })
  }

  @Test
  fun identicalExistingIdentityIsIdempotentAndNeverWrites() {
    val events = mutableListOf<String>()
    val vault = FakeVault(CANDIDATE.copyOf(), events)
    val gate = RecoveryForegroundGate().apply { markForeground() }
    val provisioner = NativeIdentityProvisioner(
      vault,
      { events += "unexpected-write" },
      RecordingDeriver(events),
      gate,
    )

    provisioner.provision(CANDIDATE.copyOf())

    assertEquals(listOf("derive", "has", "read", "derive"), events)
  }

  @Test
  fun differentExistingIdentityFailsClosed() {
    val events = mutableListOf<String>()
    val vault = FakeVault("different words".toByteArray(), events)
    val gate = RecoveryForegroundGate().apply { markForeground() }
    val provisioner = NativeIdentityProvisioner(
      vault,
      { events += "unexpected-write" },
      RecordingDeriver(events),
      gate,
    )

    assertThrows(IllegalStateException::class.java) {
      provisioner.provision(CANDIDATE.copyOf())
    }
    assertFalse(events.contains("unexpected-write"))
  }

  @Test
  fun backgroundAfterCandidateVerificationPreventsDurableWrite() {
    val events = mutableListOf<String>()
    val vault = FakeVault(events = events)
    val gate = RecoveryForegroundGate().apply { markForeground() }
    val deriver = RecoveryIdentityDeriver { mnemonic ->
      events += "derive"
      gate.markBackground()
      MessageDigest.getInstance("SHA-256").digest(mnemonic)
    }
    val provisioner = NativeIdentityProvisioner(
      vault,
      { events += "unexpected-write" },
      deriver,
      gate,
    )

    assertThrows(RecoveryNotForegroundException::class.java) {
      provisioner.provision(CANDIDATE.copyOf())
    }
    assertFalse(events.contains("unexpected-write"))
  }

  @Test
  fun backgroundDuringClaimedWriteIsNonBlockingAndVerifiedCommitCompletes() {
    val events = mutableListOf<String>()
    val vault = FakeVault(events = events)
    val gate = RecoveryForegroundGate().apply { markForeground() }
    val storeStarted = CountDownLatch(1)
    val releaseStore = CountDownLatch(1)
    val failure = AtomicReference<Throwable?>()
    val provisioner = NativeIdentityProvisioner(
      vault,
      { bytes ->
        storeStarted.countDown()
        check(releaseStore.await(5, TimeUnit.SECONDS)) { "store barrier timed out" }
        vault.persist(bytes)
      },
      RecordingDeriver(events),
      gate,
    )
    val worker = thread(name = "claimed-identity-write") {
      try {
        provisioner.provision(CANDIDATE.copyOf())
      } catch (error: Throwable) {
        failure.set(error)
      }
    }
    assertTrue(storeStarted.await(5, TimeUnit.SECONDS))
    assertTrue(gate.hasIrreversibleCommitClaim())

    val backgrounded = CountDownLatch(1)
    val lifecycle = thread(name = "recovery-pause") {
      gate.markBackground()
      backgrounded.countDown()
    }
    assertTrue("pause must never wait for Keystore/fsync", backgrounded.await(1, TimeUnit.SECONDS))
    lifecycle.join(1_000)
    releaseStore.countDown()
    worker.join(5_000)

    assertFalse(worker.isAlive)
    assertEquals(null, failure.get())
    assertTrue(vault.hasIdentity())
  }

  @Test
  fun publishedMatchingIdentityReconcilesAReportedWriteFailure() {
    val events = mutableListOf<String>()
    val vault = FakeVault(events = events)
    val gate = RecoveryForegroundGate().apply { markForeground() }
    val provisioner = NativeIdentityProvisioner(
      vault,
      { bytes ->
        vault.persist(bytes)
        throw IOException("simulated post-publication failure")
      },
      RecordingDeriver(events),
      gate,
    )

    provisioner.provision(CANDIDATE.copyOf())

    assertTrue(vault.hasIdentity())
  }

  @Test
  fun commitRunnerConsumesImmediatelyBeforeProvisionAndClearsOwnedBuffers() {
    val events = mutableListOf<String>()
    val flow = readyCreateFlow(events)
    val ownedIndices = flow.copyIndicesForCommit()
    var mnemonicReference: ByteArray? = null
    val runner = NativeRecoveryCommitRunner(TestDictionary()) { mnemonic ->
      events += "provision"
      mnemonicReference = mnemonic
      assertFalse(mnemonic.all { it == 0.toByte() })
    }

    runner.run(flow, ownedIndices)

    assertEquals(listOf("consume", "provision"), events.takeLast(2))
    assertTrue(ownedIndices.all { it == -1 })
    assertTrue(requireNotNull(mnemonicReference).all { it == 0.toByte() })
    assertEquals(RecoveryStage.COMMITTED, flow.stage)
    flow.close()
  }

  private fun readyCreateFlow(events: MutableList<String>): RecoveryFlowController {
    val draft = RunnerDraft(events)
    return RecoveryFlowController(draft, TestDictionary()).also { flow ->
      flow.continueFromCreateReview()
      flow.chooseChallengeWord(0)
    }
  }

  private class FakeVault(
    mnemonic: ByteArray? = null,
    private val events: MutableList<String>,
  ) : NativeIdentityVaultAccess {
    private var persisted = mnemonic

    override fun hasIdentity(): Boolean {
      events += "has"
      return persisted != null
    }

    override fun <T> withMnemonicBytes(operation: (ByteArray) -> T): T {
      events += "read"
      val copy = requireNotNull(persisted).copyOf()
      return try {
        operation(copy)
      } finally {
        copy.fill(0)
      }
    }

    fun persist(bytes: ByteArray) {
      check(persisted == null)
      persisted = bytes.copyOf()
    }
  }

  private class RecordingDeriver(
    private val events: MutableList<String>,
  ) : RecoveryIdentityDeriver {
    val returnedKeys = mutableListOf<ByteArray>()

    override fun deriveIdentityKey(mnemonicUtf8: ByteArray): ByteArray {
      events += "derive"
      return MessageDigest.getInstance("SHA-256").digest(mnemonicUtf8).also(returnedKeys::add)
    }
  }

  private class RunnerDraft(private val events: MutableList<String>) : RecoveryDraft {
    private var authorized = false
    override val mode = RecoveryMode.CREATE
    override fun wordCount(): Int = 12
    override fun wordIndex(position: Int): Int = position
    override fun setImportWordIndex(position: Int, index: Int) = error("not restore")
    override fun validateImport(): Boolean = false
    override fun challengeCount(): Int = 1
    override fun challengePosition(slot: Int): Int = 0
    override fun challengeChoiceCount(): Int = 2
    override fun challengeChoiceWordIndex(slot: Int, choice: Int): Int = choice
    override fun confirmChallenge(slot: Int, chosen: Int): Boolean = (chosen == 0).also { authorized = it }
    override fun isCommitAuthorized(): Boolean = authorized
    override fun consumeCommitAuthorization(): Boolean {
      events += "consume"
      return authorized.also { authorized = false }
    }
    override fun cancel() = Unit
    override fun close() = Unit
  }

  private class TestDictionary : RecoveryWordDictionary {
    override val size = 2048
    override fun word(index: Int): String = "word"
    override fun encodedLength(index: Int): Int = 4
    override fun copyEncodedWord(index: Int, destination: ByteArray, offset: Int): Int {
      destination[offset] = 'w'.code.toByte()
      destination[offset + 1] = 'o'.code.toByte()
      destination[offset + 2] = 'r'.code.toByte()
      destination[offset + 3] = 'd'.code.toByte()
      return offset + 4
    }
    override fun findPrefix(prefix: CharArray, length: Int, limit: Int): IntArray = IntArray(0)
  }

  companion object {
    private val CANDIDATE = "abandon abandon abandon about".toByteArray()
  }
}
