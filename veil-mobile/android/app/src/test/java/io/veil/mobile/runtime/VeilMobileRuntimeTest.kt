package io.veil.mobile.runtime

import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.util.Base64
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VeilMobileRuntimeTest {
  @Test
  fun sessionConnectionAndLockPublishSeparatePredictableStates() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val runtime = runtime(executor, fakeSession)
    try {
      assertTrue(runtime.snapshot().identityExists)
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
      assertEquals(NativeConnectionState.DISCONNECTED, runtime.snapshot().connectionState)

      assertEquals(NativeSessionState.OPEN, runtime.openSession().sessionState)
      val binding = runtime.connect("https://CHAT.Example")
      assertEquals("https://chat.example:443", binding.canonicalServerOrigin)
      assertEquals("wss://chat.example:443/ws", fakeSession.websocketUrl)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)

      assertEquals(NativeConnectionState.DISCONNECTED, runtime.disconnect().connectionState)
      assertFalse(fakeSession.closed)
      val locked = runtime.lockSession()
      assertEquals(NativeSessionState.LOCKED, locked.sessionState)
      assertTrue(fakeSession.closed)
      assertNull(locked.binding)
    } finally {
      executor.shutdownNow()
    }
  }

  @Test
  fun pendingPassNeverEntersSnapshotAndClearsOnlyAfterSuccess() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val passStore = deterministicPassStore()
    val runtime = runtime(executor, fakeSession, passStore)
    val tokenBytes = ByteArray(32) { 0x5a.toByte() }
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes)
    try {
      runtime.openSession()
      assertTrue(runtime.consumeEnrollmentUri("https://access.example/enroll#invite=$token"))
      val pending = runtime.snapshot().pendingAccessPass!!
      assertFalse(pending.toString().contains(token))

      runtime.connectPendingAccessPass(pending.flowId)
      assertArrayEquals(tokenBytes, fakeSession.lastAccessPass)
      assertNull(runtime.snapshot().pendingAccessPass)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun failedEnrollmentConnectKeepsPassAndReturnsOnlySanitizedPublicError() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession(connectFailure = IllegalStateException("secret-token https://internal/path"))
    val runtime = runtime(executor, fakeSession, deterministicPassStore())
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 0x31 })
    try {
      runtime.openSession()
      runtime.consumeEnrollmentUri("https://access.example/enroll#invite=$token")
      val pending = runtime.snapshot().pendingAccessPass!!

      val error = assertThrows(VeilMobileRuntimeException::class.java) {
        runtime.connectPendingAccessPass(pending.flowId)
      }
      assertEquals("E_VEIL_CONNECT", error.code)
      assertEquals("Unable to authenticate with the Veil Node", error.message)
      assertFalse(error.message.orEmpty().contains(token))
      assertEquals(pending.flowId, runtime.snapshot().pendingAccessPass?.flowId)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun explicitLockClearsAnUnredeemedPass() {
    val executor = daemonExecutor()
    val runtime = runtime(executor, FakeSession(), deterministicPassStore())
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 0x22 })
    try {
      runtime.openSession()
      runtime.consumeEnrollmentUri("https://access.example/enroll#invite=$token")
      assertTrue(runtime.snapshot().pendingAccessPass != null)

      val snapshot = runtime.lockSession()
      assertNull(snapshot.pendingAccessPass)
      assertEquals(NativeSessionState.LOCKED, snapshot.sessionState)
    } finally {
      executor.shutdownNow()
    }
  }

  private fun runtime(
    executor: ExecutorService,
    session: FakeSession,
    passStore: NodeAccessPassStore = deterministicPassStore(),
  ): VeilMobileRuntime = VeilMobileRuntime(
    vault = FakeVault(),
    passStore = passStore,
    sessionFactory = NativeMobileSessionFactory { mnemonic, path ->
      assertArrayEquals(TEST_MNEMONIC, mnemonic)
      assertEquals("/private/veil/account-v1.db", path)
      session
    },
    executor = executor,
    databasePathProvider = { "/private/veil/account-v1.db" },
  )

  private fun deterministicPassStore(): NodeAccessPassStore = NodeAccessPassStore(
    clockMillis = { 1_000L },
    randomBytes = { output -> output.fill(0x44) },
  )

  private fun daemonExecutor(): ExecutorService = Executors.newSingleThreadExecutor { operation ->
    Thread(operation, "veil-runtime-test").apply { isDaemon = true }
  }

  private class FakeVault : NativeIdentityVaultAccess {
    override fun hasIdentity(): Boolean = true

    override fun <T> withMnemonicBytes(operation: (ByteArray) -> T): T {
      val mnemonic = TEST_MNEMONIC.copyOf()
      return try {
        operation(mnemonic)
      } finally {
        mnemonic.fill(0)
      }
    }
  }

  private class FakeSession(
    private val connectFailure: Throwable? = null,
  ) : NativeMobileSession {
    var websocketUrl: String? = null
    var lastAccessPass: ByteArray? = null
    var closed = false

    override fun connect(websocketUrl: String, canonicalOrigin: String): PublicAuthenticatedBinding {
      connectFailure?.let { throw it }
      this.websocketUrl = websocketUrl
      return PublicAuthenticatedBinding(canonicalOrigin, USER_ID)
    }

    override fun connectWithNodeAccessPass(
      websocketUrl: String,
      canonicalOrigin: String,
      nodeAccessPass: ByteArray,
    ): PublicAuthenticatedBinding {
      connectFailure?.let { throw it }
      this.websocketUrl = websocketUrl
      lastAccessPass = nodeAccessPass.copyOf()
      return PublicAuthenticatedBinding(canonicalOrigin, USER_ID)
    }

    override fun disconnect() = Unit

    override fun close() {
      closed = true
      lastAccessPass?.fill(0)
    }
  }

  companion object {
    private val TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      .toByteArray()
    private const val USER_ID = "550e8400-e29b-41d4-a716-446655440001"
  }
}
