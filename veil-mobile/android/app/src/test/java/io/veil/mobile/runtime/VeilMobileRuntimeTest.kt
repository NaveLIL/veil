package io.veil.mobile.runtime

import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CopyOnWriteArrayList
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
      cancellationObservedUnderStateLock.set(Thread.holdsLock(checkNotNull(field.get(runtime))))
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
  fun snapshotPublicationCannotReorderConnectedAfterABackgroundLock() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val runtime = runtime(executor, fakeSession)
    val connectedPublicationEntered = CountDownLatch(1)
    val releaseConnectedPublication = CountDownLatch(1)
    val connectFinished = CountDownLatch(1)
    val observed = CopyOnWriteArrayList<VeilMobileRuntimeSnapshot>()
    runtime.openSession()
    runtime.addListener { snapshot ->
      if (snapshot.connectionState == NativeConnectionState.CONNECTED) {
        connectedPublicationEntered.countDown()
        check(releaseConnectedPublication.await(5, TimeUnit.SECONDS)) {
          "connected publication barrier timed out"
        }
      }
    }
    runtime.addListener { snapshot -> observed.add(snapshot) }

    val connector = thread(name = "veil-connect-publication") {
      try {
        runtime.connect("https://access.example")
      } finally {
        connectFinished.countDown()
      }
    }
    try {
      assertTrue(connectedPublicationEntered.await(5, TimeUnit.SECONDS))
      val background = thread(name = "veil-background-publication") {
        runtime.lockForBackground()
      }
      assertTrue(
        "background state did not become fail-closed",
        awaitCondition { runtime.snapshot().sessionState == NativeSessionState.LOCKED },
      )

      releaseConnectedPublication.countDown()
      assertTrue(connectFinished.await(5, TimeUnit.SECONDS))
      connector.join(5_000)
      background.join(5_000)
      awaitRuntimeIdle(runtime)

      val connectedIndex = observed.indexOfFirst {
        it.connectionState == NativeConnectionState.CONNECTED
      }
      val terminalIndex = observed.indexOfFirst {
        it.sessionState == NativeSessionState.CLOSING || it.sessionState == NativeSessionState.LOCKED
      }
      assertTrue("CONNECTED was never published", connectedIndex >= 0)
      assertTrue("fail-closed state must publish after CONNECTED", terminalIndex > connectedIndex)
      assertFalse(
        observed.drop(terminalIndex).any { it.connectionState == NativeConnectionState.CONNECTED },
      )
      assertEquals(NativeSessionState.LOCKED, observed.last().sessionState)
    } finally {
      releaseConnectedPublication.countDown()
      connector.join(5_000)
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
  fun supersededBackgroundEpochStillRevokesItsDetachedDirectLease() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val runtime = runtime(executor, fakeSession)
    val blockerEntered = CountDownLatch(1)
    val releaseBlocker = CountDownLatch(1)
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      fakeSession.lifecycleEvents.clear()
      runtime.execute {
        blockerEntered.countDown()
        check(releaseBlocker.await(5, TimeUnit.SECONDS)) { "runtime executor barrier timed out" }
      }
      assertTrue(blockerEntered.await(5, TimeUnit.SECONDS))

      runtime.lockForBackground()
      runtime.markForeground()
      runtime.lockForBackground()
      releaseBlocker.countDown()
      awaitRuntimeIdle(runtime)

      assertEquals(1, fakeSession.directLeaseCancellations)
      assertTrue(fakeSession.closed)
      assertTrue(
        fakeSession.lifecycleEvents.indexOf("cancel-direct") <
          fakeSession.lifecycleEvents.indexOf("close"),
      )
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
    } finally {
      releaseBlocker.countDown()
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
      directTransport = PassiveDirectTransport(),
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
  fun directDirectoryPublishesOnlyTheCompleteAuthenticatedPaginationResult() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val first = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val second = directConversation("20", "Bob", "21", "bob", needsPreKey = false)
    fakeSession.directoryInstalls.clear()
    fakeSession.directoryInstalls.add(
      NativeDirectDirectoryInstall(listOf(first), directoryComplete = false),
    )
    fakeSession.directoryInstalls.add(
      NativeDirectDirectoryInstall(listOf(second), directoryComplete = true),
    )
    val firstBody = "first-page-with-native-key-material".toByteArray()
    val secondBody = "second-page-with-native-key-material".toByteArray()
    try {
      runtime.openSession()
      runtime.connect("https://access.example")

      assertEquals(NativeDirectDirectoryState.SYNCING, runtime.snapshot().directDirectoryState)
      assertTrue(runtime.snapshot().directConversations.isEmpty())
      assertFalse(runtime.snapshot().directoryReady)
      assertEquals(1, transport.pendingCount())

      transport.completeNext(NativeDirectHttpResult.Success(firstBody))
      awaitRuntimeIdle(runtime)

      assertTrue(firstBody.all { it == 0.toByte() })
      assertEquals(NativeDirectDirectoryState.SYNCING, runtime.snapshot().directDirectoryState)
      assertTrue("partial pages must never be published", runtime.snapshot().directConversations.isEmpty())
      assertEquals(1, transport.pendingCount())

      transport.completeNext(NativeDirectHttpResult.Success(secondBody))
      awaitRuntimeIdle(runtime)

      val complete = runtime.snapshot()
      assertTrue(secondBody.all { it == 0.toByte() })
      assertEquals(NativeDirectDirectoryState.SYNCHRONIZED, complete.directDirectoryState)
      assertEquals(listOf(first, second), complete.directConversations)
      assertEquals(NativeConnectionState.CONNECTED, complete.connectionState)
      assertFalse("history is not synchronized yet", complete.directoryReady)
      assertEquals(2, fakeSession.installedResponseCopies.size)
      assertEquals(2, transport.requests.size)
      assertTrue(transport.requests.all { it.canonicalServerOrigin == "https://access.example:443" })
      assertTrue(transport.requests.all { it.responseLimitBytes == NativeDirectHttpLimits.DIRECTORY_BYTES })
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundCancelsDirectHttpAndLeaseBeforeClosingAndDropsLateSuccess() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val lateBody = "late-page-with-native-key-material".toByteArray()
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      val pendingCall = transport.calls.single()
      fakeSession.lifecycleEvents.clear()

      runtime.lockForBackground()
      assertTrue("HTTP cancellation must be immediate", pendingCall.cancelled.get())
      transport.completeNext(NativeDirectHttpResult.Success(lateBody))
      awaitRuntimeIdle(runtime)

      val locked = runtime.snapshot()
      assertTrue(lateBody.all { it == 0.toByte() })
      assertEquals(NativeSessionState.LOCKED, locked.sessionState)
      assertEquals(NativeDirectDirectoryState.IDLE, locked.directDirectoryState)
      assertTrue(locked.directConversations.isEmpty())
      assertEquals(0, fakeSession.installedResponseCopies.size)
      assertEquals(listOf("cancel-direct", "disconnect", "close"), fakeSession.lifecycleEvents)
    } finally {
      executor.shutdownNow()
    }
  }

  @Test
  fun directTransportFailureFailsClosedAndAllowsAFreshConnectionGeneration() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      transport.completeNext(NativeDirectHttpResult.Failure(NativeDirectHttpFailure.NETWORK))
      awaitRuntimeIdle(runtime)

      val failed = runtime.snapshot()
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertEquals(NativeDirectDirectoryState.ERROR, failed.directDirectoryState)
      assertNull(failed.binding)
      assertTrue(failed.directConversations.isEmpty())
      assertFalse(failed.directoryReady)
      assertEquals(1, fakeSession.directLeaseCancellations)

      runtime.connect("https://access.example")
      val retried = runtime.snapshot()
      assertEquals(NativeConnectionState.CONNECTED, retried.connectionState)
      assertEquals(NativeDirectDirectoryState.SYNCING, retried.directDirectoryState)
      assertEquals(1, transport.pendingCount())
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun directLeaseMustMatchTheExactAuthenticatedBindingBeforeAnyHttpRequest() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      directLeaseUserOverride = "550e8400-e29b-41d4-a716-446655440099"
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    try {
      runtime.openSession()
      val error = assertThrows(VeilMobileRuntimeException::class.java) {
        runtime.connect("https://access.example")
      }

      assertEquals("E_VEIL_SYNC", error.code)
      assertEquals("Unable to verify the Direct directory", error.message)
      assertEquals(0, transport.requests.size)
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertEquals(NativeDirectDirectoryState.ERROR, runtime.snapshot().directDirectoryState)
      assertNull(runtime.snapshot().binding)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun duplicateAcrossDirectoryPagesFailsWithoutPublishingPartialRows() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val duplicate = directConversation("30", "Mallory", "31", "mallory", needsPreKey = true)
    fakeSession.directoryInstalls.clear()
    fakeSession.directoryInstalls.add(
      NativeDirectDirectoryInstall(listOf(duplicate), directoryComplete = false),
    )
    fakeSession.directoryInstalls.add(
      NativeDirectDirectoryInstall(listOf(duplicate), directoryComplete = true),
    )
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      transport.completeNext(NativeDirectHttpResult.Success("page-one".toByteArray()))
      awaitRuntimeIdle(runtime)
      transport.completeNext(NativeDirectHttpResult.Success("page-two".toByteArray()))
      awaitRuntimeIdle(runtime)

      val failed = runtime.snapshot()
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertEquals(NativeDirectDirectoryState.ERROR, failed.directDirectoryState)
      assertTrue(failed.directConversations.isEmpty())
      assertFalse(failed.directoryReady)
      assertNull(failed.binding)
    } finally {
      runtime.lockSession()
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
    assertFalse(install.toString().contains("Alice"))
    assertFalse(install.toString().contains("alice"))

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
    directTransport: NativeDirectHttpExecutor = PassiveDirectTransport(),
  ): VeilMobileRuntime = VeilMobileRuntime(
      vault = vault,
      passStore = passStore,
      sessionFactory = NativeMobileSessionFactory { mnemonic, path ->
        assertArrayEquals(TEST_MNEMONIC, mnemonic)
        assertEquals("/private/veil/account-v1.db", path)
        session
      },
      cancellationFactory = cancellationFactory,
      directTransport = directTransport,
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

  private fun awaitRuntimeIdle(runtime: VeilMobileRuntime) {
    val drained = CountDownLatch(1)
    runtime.execute { drained.countDown() }
    assertTrue("runtime executor did not drain", drained.await(5, TimeUnit.SECONDS))
  }

  private fun awaitCondition(condition: () -> Boolean): Boolean {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
    while (System.nanoTime() < deadline) {
      if (condition()) return true
      Thread.yield()
    }
    return condition()
  }

  private fun directConversation(
    conversationSuffix: String,
    name: String,
    peerSuffix: String,
    peerUsername: String,
    needsPreKey: Boolean,
  ): NativeDirectConversationInstall = NativeDirectConversationInstall(
    conversationId = "550e8400-e29b-41d4-a716-4466554400$conversationSuffix",
    name = name,
    peerUserId = "550e8400-e29b-41d4-a716-4466554400$peerSuffix",
    peerUsername = peerUsername,
    needsPreKey = needsPreKey,
  )

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
    var canonicalOrigin: String? = null
    var lastAccessPass: ByteArray? = null
    var closed = false
    var directLeaseCancellations = 0
    var directLeaseUserOverride: String? = null
    var directoryRequestCount = 0
    val directoryInstalls = ArrayDeque<NativeDirectDirectoryInstall>().apply {
      add(NativeDirectDirectoryInstall(emptyList(), directoryComplete = true))
    }
    val installedResponseCopies = CopyOnWriteArrayList<ByteArray>()
    val lifecycleEvents = CopyOnWriteArrayList<String>()
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
      this.canonicalOrigin = canonicalOrigin
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
      this.canonicalOrigin = canonicalOrigin
      lastAccessPass = nodeAccessPass.copyOf()
      return PublicAuthenticatedBinding(canonicalOrigin, USER_ID)
    }

    override fun beginDirectSync(): NativeDirectSyncLease = NativeDirectSyncLease(
      leaseToken = "test-direct-lease",
      canonicalServerOrigin = checkNotNull(canonicalOrigin),
      userId = directLeaseUserOverride ?: USER_ID,
    )

    override fun prepareDirectDirectoryRequest(leaseToken: String): NativeDirectRestRequest {
      directoryRequestCount += 1
      return NativeDirectRestRequest(
        requestToken = "test-directory-request-$directoryRequestCount",
        requestTarget = if (directoryRequestCount == 1) {
          "/v1/conversations?limit=100"
        } else {
          "/v1/conversations?cursor=cursor-$directoryRequestCount&limit=100"
        },
      )
    }

    override fun installDirectDirectoryPage(
      leaseToken: String,
      requestToken: String,
      response: ByteArray,
    ): NativeDirectDirectoryInstall {
      installedResponseCopies.add(response.copyOf())
      return directoryInstalls.removeFirst()
    }

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
      directLeaseCancellations += 1
      lifecycleEvents.add("cancel-direct")
    }

    override fun signRestRequest(
      canonicalServerOrigin: String,
      method: String,
      requestTarget: String,
      body: ByteArray,
    ): NativeRestSignature = NativeRestSignature(
      userId = USER_ID,
      timestampMs = "1712345678901",
      signatureBase64 = Base64.getEncoder().encodeToString(ByteArray(64)),
    )

    override fun disconnect() {
      lifecycleEvents.add("disconnect")
    }

    override fun close() {
      closedDuringConnect.set(inConnect.get())
      closed = true
      lifecycleEvents.add("close")
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

  private class PassiveDirectTransport : NativeDirectHttpExecutor {
    override fun execute(
      request: NativeDirectHttpRequest,
      callback: NativeDirectHttpCallback,
    ): NativeDirectHttpCall = object : NativeDirectHttpCall {
      override fun cancel() = Unit
    }
  }

  private class ControllableDirectTransport : NativeDirectHttpExecutor {
    private data class Pending(
      val callback: NativeDirectHttpCallback,
      val call: TestDirectHttpCall,
    )

    private val pending = ArrayDeque<Pending>()
    val requests = CopyOnWriteArrayList<NativeDirectHttpRequest>()
    val calls = CopyOnWriteArrayList<TestDirectHttpCall>()

    override fun execute(
      request: NativeDirectHttpRequest,
      callback: NativeDirectHttpCallback,
    ): NativeDirectHttpCall {
      val call = TestDirectHttpCall()
      synchronized(this) {
        requests.add(request)
        calls.add(call)
        pending.add(Pending(callback, call))
      }
      return call
    }

    fun pendingCount(): Int = synchronized(this) { pending.size }

    fun completeNext(result: NativeDirectHttpResult) {
      val selected = synchronized(this) { pending.removeFirst() }
      // Deliberately permit a completion after cancel to model a callback that
      // already won the transport's terminal CAS before lifecycle detachment.
      selected.callback.onComplete(result)
    }

    class TestDirectHttpCall : NativeDirectHttpCall {
      val cancelled = AtomicBoolean(false)

      override fun cancel() {
        cancelled.set(true)
      }
    }
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
