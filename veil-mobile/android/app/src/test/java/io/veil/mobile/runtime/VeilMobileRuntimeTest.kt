package io.veil.mobile.runtime

import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.veil_ffi.MobileDirectConversationData
import uniffi.veil_ffi.MobileDirectDirectoryPageData
import uniffi.veil_ffi.MobileDirectPreKeyResult
import uniffi.veil_ffi.MobileDirectRestRequest
import uniffi.veil_ffi.MobileDirectSyncLease
import uniffi.veil_ffi.RestSignatureData

class VeilMobileRuntimeTest {
  @Test
  fun freshRuntimeRejectsAccountAccessUntilForegroundAuthorityIsGranted() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val runtime = runtime(executor, fakeSession, markForeground = false)
    try {
      val openError = assertThrows(VeilMobileRuntimeException::class.java) {
        runtime.openSession()
      }
      assertEquals("E_VEIL_LOCKED", openError.code)

      val connectError = assertThrows(VeilMobileRuntimeException::class.java) {
        runtime.connect("https://access.example")
      }
      assertEquals("E_VEIL_LOCKED", connectError.code)
      assertFalse(fakeSession.closed)

      runtime.markForeground()
      assertEquals(NativeSessionState.OPEN, runtime.openSession().sessionState)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

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

  @Test
  fun liveSessionDoesNotDependOnASecondVaultRead() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val vault = FakeVault()
    val runtime = runtime(executor, fakeSession, vault = vault)
    try {
      runtime.openSession()
      vault.failHasIdentity = true

      val snapshot = runtime.snapshot()
      assertTrue(snapshot.identityExists)
      assertEquals(NativeSessionState.OPEN, snapshot.sessionState)
      assertEquals(NativeSessionState.OPEN, runtime.openSession().sessionState)
      assertFalse(fakeSession.closed)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundCancellationPreventsAStaleSuccessfulConnectFromPublishing() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession(blockUntilCancelled = true, succeedAfterCancellation = true)
    val passStore = deterministicPassStore()
    lateinit var runtime: VeilMobileRuntime
    val cancellationObservedUnderStateLock = AtomicBoolean(false)
    val cancellation = FakeCancellation {
      val field = VeilMobileRuntime::class.java.getDeclaredField("stateLock")
      field.isAccessible = true
      cancellationObservedUnderStateLock.set(Thread.holdsLock(field.get(runtime)))
    }
    runtime = runtime(
      executor,
      fakeSession,
      passStore,
      cancellationFactory = NativeConnectCancellationFactory { cancellation },
    )
    val connectedWasPublished = AtomicBoolean(false)
    val connectError = AtomicReference<VeilMobileRuntimeException?>()
    val connectFinished = CountDownLatch(1)
    val executorDrained = CountDownLatch(1)
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 0x66 })
    runtime.addListener { snapshot ->
      if (snapshot.connectionState == NativeConnectionState.CONNECTED) connectedWasPublished.set(true)
    }
    try {
      runtime.openSession()
      runtime.consumeEnrollmentUri("https://access.example/enroll#invite=$token")
      val flowId = runtime.snapshot().pendingAccessPass!!.flowId
      runtime.execute {
        try {
          runtime.connectPendingAccessPass(flowId)
        } catch (error: VeilMobileRuntimeException) {
          connectError.set(error)
        } finally {
          connectFinished.countDown()
        }
      }
      assertTrue(fakeSession.connectStarted.await(5, TimeUnit.SECONDS))

      runtime.lockForBackground()
      assertEquals(NativeSessionState.CLOSING, runtime.snapshot().sessionState)
      assertNull(runtime.snapshot().binding)
      assertNull(runtime.snapshot().pendingAccessPass)
      runtime.execute { executorDrained.countDown() }

      assertTrue(connectFinished.await(5, TimeUnit.SECONDS))
      assertTrue(executorDrained.await(5, TimeUnit.SECONDS))
      assertEquals("E_VEIL_CANCELLED", connectError.get()?.code)
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
      assertNull(runtime.snapshot().binding)
      assertFalse(connectedWasPublished.get())
      assertTrue(
        "background cancellation must be linearized under the runtime state lock",
        cancellationObservedUnderStateLock.get(),
      )
      assertTrue(fakeSession.closed)
      assertFalse(fakeSession.closedDuringConnect.get())
    } finally {
      executor.shutdownNow()
    }
  }

  @Test
  fun foregroundResumeCannotResurrectAQueuedBackgroundLock() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val runtime = runtime(executor, fakeSession)
    val blockerEntered = CountDownLatch(1)
    val releaseBlocker = CountDownLatch(1)
    val executorDrained = CountDownLatch(1)
    try {
      runtime.openSession()
      runtime.execute {
        blockerEntered.countDown()
        check(releaseBlocker.await(5, TimeUnit.SECONDS)) { "runtime executor barrier timed out" }
      }
      assertTrue(blockerEntered.await(5, TimeUnit.SECONDS))

      runtime.lockForBackground()
      assertEquals(NativeSessionState.CLOSING, runtime.snapshot().sessionState)
      assertEquals(NativeSessionState.CLOSING, runtime.markForeground().sessionState)
      releaseBlocker.countDown()
      runtime.execute { executorDrained.countDown() }

      assertTrue(executorDrained.await(5, TimeUnit.SECONDS))
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
      assertTrue(fakeSession.closed)
    } finally {
      releaseBlocker.countDown()
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundDuringOpenRejectsAndClosesTheLateCandidate() {
    val executor = daemonExecutor()
    val candidate = FakeSession()
    val factoryEntered = CountDownLatch(1)
    val releaseFactory = CountDownLatch(1)
    val openFinished = CountDownLatch(1)
    val executorDrained = CountDownLatch(1)
    val openError = AtomicReference<VeilMobileRuntimeException?>()
    val runtime = VeilMobileRuntime(
      vault = FakeVault(),
      passStore = deterministicPassStore(),
      sessionFactory = NativeMobileSessionFactory { mnemonic, path ->
        assertArrayEquals(TEST_MNEMONIC, mnemonic)
        assertEquals("/private/veil/account-v1.db", path)
        factoryEntered.countDown()
        check(releaseFactory.await(5, TimeUnit.SECONDS)) { "session factory barrier timed out" }
        candidate
      },
      cancellationFactory = NativeConnectCancellationFactory { FakeCancellation() },
      executor = executor,
      databasePathProvider = { "/private/veil/account-v1.db" },
    )
    runtime.markForeground()
    val opener = thread(name = "veil-session-open") {
      try {
        runtime.openSession()
      } catch (error: VeilMobileRuntimeException) {
        openError.set(error)
      } finally {
        openFinished.countDown()
      }
    }
    try {
      assertTrue(factoryEntered.await(5, TimeUnit.SECONDS))
      runtime.lockForBackground()
      runtime.markForeground()
      runtime.execute { executorDrained.countDown() }
      assertTrue(executorDrained.await(5, TimeUnit.SECONDS))
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)

      releaseFactory.countDown()
      assertTrue(openFinished.await(5, TimeUnit.SECONDS))
      opener.join()
      assertEquals("E_VEIL_LOCKED", openError.get()?.code)
      assertTrue(candidate.closed)
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
    } finally {
      releaseFactory.countDown()
      executor.shutdownNow()
    }
  }

  @Test
  fun generatedDirectCapabilitiesMapToRedactingNativeOnlyDtos() {
    val leaseToken = "lease-capability-that-must-not-be-logged"
    val requestToken = "request-capability-that-must-not-be-logged"
    val requestTarget = "/v1/prekeys/peer-identity-key-hex-must-not-be-logged"
    val signatureValue = "signed-header-that-must-not-be-logged"

    val lease = MobileDirectSyncLease(
      token = leaseToken,
      canonicalServerOrigin = "https://chat.example:443",
      userId = USER_ID,
    ).toNativeDirectSyncLease()
    val request = MobileDirectRestRequest(
      requestToken = requestToken,
      requestTarget = requestTarget,
    ).toNativeDirectRestRequest()
    val signature = RestSignatureData(
      userId = USER_ID,
      timestampMs = "1712345678901",
      signatureBase64 = signatureValue,
    ).toNativeRestSignature()

    assertEquals(leaseToken, lease.leaseToken)
    assertEquals("https://chat.example:443", lease.canonicalServerOrigin)
    assertEquals(USER_ID, lease.userId)
    assertEquals(requestToken, request.requestToken)
    assertEquals(requestTarget, request.requestTarget)
    assertEquals(USER_ID, signature.userId)
    assertEquals("1712345678901", signature.timestampMs)
    assertEquals(signatureValue, signature.signatureBase64)
    assertFalse(lease.toString().contains(leaseToken))
    assertFalse(request.toString().contains(requestToken))
    assertFalse(request.toString().contains(requestTarget))
    assertFalse(signature.toString().contains(signatureValue))
  }

  @Test
  fun directoryInstallMappingCopiesOnlyPublicRowsAndDropsPeerKeyMaterial() {
    val peerIdentityKey = "identity-key-hex-must-remain-native"
    val peerSigningKey = "signing-key-hex-must-remain-native"
    val generatedConversation = MobileDirectConversationData(
      conversationId = "550e8400-e29b-41d4-a716-446655440010",
      name = "Alice",
      peerUserId = "550e8400-e29b-41d4-a716-446655440011",
      peerUsername = "alice",
      peerIdentityKeyHex = peerIdentityKey,
      peerSigningKeyHex = peerSigningKey,
      needsPrekey = true,
    )
    val generatedRows = mutableListOf(generatedConversation)
    val install = MobileDirectDirectoryPageData(
      conversations = generatedRows,
      nextCursor = "opaque-server-cursor",
      skippedNonDirect = 2u,
      directoryComplete = false,
    ).toNativeDirectDirectoryInstall()

    assertFalse(install.directoryComplete)
    assertEquals(1, install.conversations.size)
    assertEquals("Alice", install.conversations.single().name)
    assertEquals("alice", install.conversations.single().peerUsername)
    assertTrue(install.conversations.single().needsPreKey)
    val installFields = NativeDirectConversationInstall::class.java.declaredFields.map { it.name }.toSet()
    assertFalse(installFields.contains("peerIdentityKeyHex"))
    assertFalse(installFields.contains("peerSigningKeyHex"))
    assertFalse(install.toString().contains(peerIdentityKey))
    assertFalse(install.toString().contains(peerSigningKey))

    generatedConversation.name = "mutated-after-mapping"
    generatedRows.clear()
    assertEquals(1, install.conversations.size)
    assertEquals("Alice", install.conversations.single().name)
  }

  @Test
  fun preKeyInstallMappingIsClosedOverKnownNativeStatuses() {
    assertEquals(
      NativeDirectPreKeyInstallStatus.ESTABLISHED,
      MobileDirectPreKeyResult("established").toNativeDirectPreKeyInstall().status,
    )
    assertEquals(
      NativeDirectPreKeyInstallStatus.ALREADY_ESTABLISHED,
      MobileDirectPreKeyResult("already_established").toNativeDirectPreKeyInstall().status,
    )

    val error = assertThrows(IllegalStateException::class.java) {
      MobileDirectPreKeyResult("unexpected-secret-status").toNativeDirectPreKeyInstall()
    }
    assertEquals("native Direct prekey install returned an unsupported status", error.message)
    assertFalse(error.message.orEmpty().contains("unexpected-secret-status"))
  }

  private fun runtime(
    executor: ExecutorService,
    session: FakeSession,
    passStore: NodeAccessPassStore = deterministicPassStore(),
    vault: NativeIdentityVaultAccess = FakeVault(),
    markForeground: Boolean = true,
    cancellationFactory: NativeConnectCancellationFactory =
      NativeConnectCancellationFactory { FakeCancellation() },
  ): VeilMobileRuntime = VeilMobileRuntime(
      vault = vault,
      passStore = passStore,
      sessionFactory = NativeMobileSessionFactory { mnemonic, path ->
        assertArrayEquals(TEST_MNEMONIC, mnemonic)
        assertEquals("/private/veil/account-v1.db", path)
        session
      },
      cancellationFactory = cancellationFactory,
      executor = executor,
      databasePathProvider = { "/private/veil/account-v1.db" },
    ).also { runtime ->
      if (markForeground) runtime.markForeground()
    }

  private fun deterministicPassStore(): NodeAccessPassStore = NodeAccessPassStore(
    clockMillis = { 1_000L },
    randomBytes = { output -> output.fill(0x44) },
  )

  private fun daemonExecutor(): ExecutorService = Executors.newSingleThreadExecutor { operation ->
    Thread(operation, "veil-runtime-test").apply { isDaemon = true }
  }

  private class FakeVault : NativeIdentityVaultAccess {
    var failHasIdentity = false

    override fun hasIdentity(): Boolean {
      if (failHasIdentity) throw IllegalStateException("vault temporarily unavailable")
      return true
    }

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
    private val blockUntilCancelled: Boolean = false,
    private val succeedAfterCancellation: Boolean = false,
  ) : NativeMobileSession {
    var websocketUrl: String? = null
    var lastAccessPass: ByteArray? = null
    var closed = false
    val connectStarted = CountDownLatch(1)
    val closedDuringConnect = AtomicBoolean(false)
    private val inConnect = AtomicBoolean(false)

    override fun connect(
      websocketUrl: String,
      canonicalOrigin: String,
      cancellation: NativeConnectCancellation,
    ): PublicAuthenticatedBinding {
      awaitCancellationIfRequested(cancellation)
      connectFailure?.let { throw it }
      this.websocketUrl = websocketUrl
      return PublicAuthenticatedBinding(canonicalOrigin, USER_ID)
    }

    override fun connectWithNodeAccessPass(
      websocketUrl: String,
      canonicalOrigin: String,
      nodeAccessPass: ByteArray,
      cancellation: NativeConnectCancellation,
    ): PublicAuthenticatedBinding {
      awaitCancellationIfRequested(cancellation)
      connectFailure?.let { throw it }
      this.websocketUrl = websocketUrl
      lastAccessPass = nodeAccessPass.copyOf()
      return PublicAuthenticatedBinding(canonicalOrigin, USER_ID)
    }

    override fun beginDirectSync(): NativeDirectSyncLease = unexpectedDirectBridgeCall()

    override fun prepareDirectDirectoryRequest(leaseToken: String): NativeDirectRestRequest =
      unexpectedDirectBridgeCall()

    override fun installDirectDirectoryPage(
      leaseToken: String,
      requestToken: String,
      response: ByteArray,
    ): NativeDirectDirectoryInstall = unexpectedDirectBridgeCall()

    override fun prepareDirectPreKeyRequest(
      leaseToken: String,
      conversationId: String,
    ): NativeDirectRestRequest = unexpectedDirectBridgeCall()

    override fun installDirectPreKeyBundle(
      leaseToken: String,
      requestToken: String,
      conversationId: String,
      response: ByteArray,
    ): NativeDirectPreKeyInstall = unexpectedDirectBridgeCall()

    override fun cancelDirectSync(leaseToken: String) {
      unexpectedDirectBridgeCall()
    }

    override fun signRestRequest(
      canonicalServerOrigin: String,
      method: String,
      requestTarget: String,
      body: ByteArray,
    ): NativeRestSignature = unexpectedDirectBridgeCall()

    override fun disconnect() = Unit

    override fun close() {
      closedDuringConnect.set(inConnect.get())
      closed = true
      lastAccessPass?.fill(0)
    }

    private fun awaitCancellationIfRequested(cancellation: NativeConnectCancellation) {
      if (!blockUntilCancelled) return
      val fake = cancellation as FakeCancellation
      inConnect.set(true)
      connectStarted.countDown()
      check(fake.cancelled.await(5, TimeUnit.SECONDS)) { "connection cancellation timed out" }
      inConnect.set(false)
      if (!succeedAfterCancellation) {
        throw IllegalStateException("mobile connection attempt cancelled")
      }
    }

    private fun unexpectedDirectBridgeCall(): Nothing =
      throw AssertionError("Direct bridge must not be invoked by lifecycle-only runtime tests")
  }

  private class FakeCancellation(
    private val onCancel: () -> Unit = {},
  ) : NativeConnectCancellation {
    val cancelled = CountDownLatch(1)
    private val closed = AtomicBoolean(false)

    override fun cancel() {
      check(!closed.get()) { "cancellation capability used after close" }
      onCancel()
      cancelled.countDown()
    }

    override fun close() {
      closed.set(true)
    }
  }

  companion object {
    private val TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      .toByteArray()
    private const val USER_ID = "550e8400-e29b-41d4-a716-446655440001"
  }
}
