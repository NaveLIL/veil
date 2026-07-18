package io.veil.mobile.runtime

import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
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
import uniffi.veil_ffi.MobileDirectHistoryNext
import uniffi.veil_ffi.MobileDirectHistoryOutcome
import uniffi.veil_ffi.MobileDirectHistoryProgress
import uniffi.veil_ffi.MobileDirectLiveBufferProgress
import uniffi.veil_ffi.MobileDirectMessageData
import uniffi.veil_ffi.MobileDirectMessageProjection
import uniffi.veil_ffi.MobileDirectMessageProjectionAvailability
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
  fun directProjectionNeverTouchesNativePlaintextBeforeTheReadyLifecycleGate() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val runtime = runtime(executor, fakeSession)
    try {
      runtime.openSession()
      val projection = publishDirectMessagesForTest(
        runtime,
        "20000000-0000-4000-8000-000000000001",
      )
      assertEquals(
        NativeDirectMessageProjectionAvailability.UNAVAILABLE,
        projection.availability,
      )
      assertTrue(projection.messages.isEmpty())
      assertEquals(0, fakeSession.directProjectionCount)

      var invalidPublications = 0
      runtime.publishDirectMessages("not-a-canonical-uuid") { denied ->
        invalidPublications += 1
        assertEquals(NativeDirectMessageProjectionAvailability.UNAVAILABLE, denied.availability)
        assertTrue(denied.messages.isEmpty())
      }
      assertEquals(1, invalidPublications)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun directProjectionRejectsAnOldSameSessionReconnectGenerationAfterNativeReturns() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = false)
    val projectionEntered = CountDownLatch(1)
    val releaseProjection = CountDownLatch(1)
    val oldPlaintext = "plaintext owned by the revoked Direct generation"
    val projected = AtomicReference<NativeDirectMessageProjection>()
    fakeSession.directoryInstalls.clear()
    fakeSession.directoryInstalls.add(
      NativeDirectDirectoryInstall(listOf(conversation), directoryComplete = true),
    )
    try {
      runtime.openSession()
      val firstBinding = runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(NativeDirectHttpResult.Success("directory-a".toByteArray()))
      awaitRuntimeIdle(runtime)
      forceDirectoryReadyForProjectionTest(runtime)

      fakeSession.directProjection = NativeDirectMessageProjection(
        NativeDirectMessageProjectionAvailability.AVAILABLE,
        listOf(
          NativeDirectMessageView(
            messageId = "30000000-0000-4000-8000-000000000001",
            text = oldPlaintext,
            timestampMs = 1_700_000_000_123,
            direction = NativeDirectMessageDirection.INCOMING,
            delivery = NativeDirectMessageDelivery.SENT,
          ),
        ),
      )
      fakeSession.directProjectionEntered = projectionEntered
      fakeSession.directProjectionRelease = releaseProjection
      val reader = thread(name = "old-direct-projection") {
        runtime.publishDirectMessages(conversation.conversationId) { projection ->
          projected.set(projection)
        }
      }
      assertTrue("old projection did not enter native code", projectionEntered.await(5, TimeUnit.SECONDS))

      // Reconnect the same NativeMobileSession to the same public binding. A
      // value-only lifecycle check would accept the old plaintext after this
      // second Direct generation reaches Ready.
      fakeSession.directoryInstalls.add(
        NativeDirectDirectoryInstall(listOf(conversation), directoryComplete = true),
      )
      val secondBinding = runtime.connect("https://access.example")
      assertEquals(firstBinding, secondBinding)
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(NativeDirectHttpResult.Success("directory-b".toByteArray()))
      awaitRuntimeIdle(runtime)
      forceDirectoryReadyForProjectionTest(runtime)

      releaseProjection.countDown()
      reader.join(TimeUnit.SECONDS.toMillis(5))
      assertFalse("old projection reader did not finish", reader.isAlive)
      val denied = checkNotNull(projected.get())
      assertEquals(NativeDirectMessageProjectionAvailability.UNAVAILABLE, denied.availability)
      assertTrue(denied.messages.isEmpty())
      assertFalse(denied.toString().contains(oldPlaintext))
    } finally {
      releaseProjection.countDown()
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun directProjectionBridgePublicationLinearizesBeforeBackgroundRevocation() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = false)
    val publisherEntered = CountDownLatch(1)
    val releasePublisher = CountDownLatch(1)
    val backgroundAttempted = CountDownLatch(1)
    val backgroundFinished = CountDownLatch(1)
    val plaintext = "plaintext published before the background transition"
    val published = AtomicReference<NativeDirectMessageProjection>()
    fakeSession.directoryInstalls.clear()
    fakeSession.directoryInstalls.add(
      NativeDirectDirectoryInstall(listOf(conversation), directoryComplete = true),
    )
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(NativeDirectHttpResult.Success("directory-ready".toByteArray()))
      awaitRuntimeIdle(runtime)
      forceDirectoryReadyForProjectionTest(runtime)

      fakeSession.directProjectionFailure = IllegalStateException("synthetic native projection failure")
      var failurePublications = 0
      runtime.publishDirectMessages(conversation.conversationId) { denied ->
        failurePublications += 1
        assertEquals(NativeDirectMessageProjectionAvailability.UNAVAILABLE, denied.availability)
        assertTrue(denied.messages.isEmpty())
      }
      assertEquals(1, failurePublications)
      fakeSession.directProjectionFailure = null

      fakeSession.directProjection = NativeDirectMessageProjection(
        NativeDirectMessageProjectionAvailability.AVAILABLE,
        listOf(
          NativeDirectMessageView(
            messageId = "30000000-0000-4000-8000-000000000001",
            text = plaintext,
            timestampMs = 1_700_000_000_123,
            direction = NativeDirectMessageDirection.INCOMING,
            delivery = NativeDirectMessageDelivery.SENT,
          ),
        ),
      )
      val reader = thread(name = "direct-bridge-publisher") {
        runtime.publishDirectMessages(conversation.conversationId) { projection ->
          publisherEntered.countDown()
          check(releasePublisher.await(5, TimeUnit.SECONDS)) {
            "synthetic bridge publication timed out"
          }
          published.set(projection)
        }
      }
      assertTrue("bridge publisher did not enter", publisherEntered.await(5, TimeUnit.SECONDS))

      val background = thread(name = "background-during-direct-publication") {
        backgroundAttempted.countDown()
        runtime.lockForBackground()
        backgroundFinished.countDown()
      }
      assertTrue("background transition did not start", backgroundAttempted.await(5, TimeUnit.SECONDS))
      assertFalse(
        "background transition crossed an in-flight bridge publication",
        backgroundFinished.await(150, TimeUnit.MILLISECONDS),
      )

      releasePublisher.countDown()
      reader.join(TimeUnit.SECONDS.toMillis(5))
      background.join(TimeUnit.SECONDS.toMillis(5))
      assertFalse("bridge publisher did not finish", reader.isAlive)
      assertFalse("background transition did not finish", background.isAlive)
      assertTrue(backgroundFinished.await(0, TimeUnit.MILLISECONDS))
      val available = checkNotNull(published.get())
      assertEquals(NativeDirectMessageProjectionAvailability.AVAILABLE, available.availability)
      assertEquals(plaintext, available.messages.single().text)
      awaitRuntimeIdle(runtime)
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
    } finally {
      releasePublisher.countDown()
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
      completeOwnPreKeyBootstrap(runtime, transport)

      assertEquals(NativeDirectDirectoryState.SYNCING, runtime.snapshot().directDirectoryState)
      assertEquals(NativeOwnPreKeyState.PUBLISHED, runtime.snapshot().ownPreKeyState)
      assertEquals(NativeSecureSyncState.SYNCING_DIRECTORY, runtime.snapshot().secureSyncState)
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
      assertEquals(NativeDirectHistoryState.SYNCHRONIZED, complete.directHistoryState)
      assertEquals(NativeSecureSyncState.HISTORY_SYNCHRONIZED, complete.secureSyncState)
      assertEquals(listOf(first, second), complete.directConversations)
      assertEquals(NativeConnectionState.CONNECTED, complete.connectionState)
      assertFalse("deferred live events are not replayed yet", complete.directoryReady)
      assertEquals(2, fakeSession.installedResponseCopies.size)
      assertEquals(4, transport.requests.size)
      assertTrue(transport.requests.all { it.canonicalServerOrigin == "https://access.example:443" })
      assertTrue(
        transport.requests.drop(2).all {
          it.responseLimitBytes == NativeDirectHttpLimits.DIRECTORY_BYTES &&
            it.method == NativeDirectHttpMethod.GET &&
            it.body.isEmpty()
        },
      )
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun directHistoryRunsOneExactRequestAtATimeAndNeverOpensReadyBeforeLiveReplay() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    fakeSession.directoryInstalls.clear()
    fakeSession.directoryInstalls.add(
      NativeDirectDirectoryInstall(listOf(conversation), directoryComplete = true),
    )
    fakeSession.historyNexts.add(
      NativeDirectHistoryNext(
        request = NativeDirectRestRequest(
          requestToken = "history-page-one",
          method = "GET",
          requestTarget = "/v1/messages/${conversation.conversationId}?limit=25",
          body = byteArrayOf(),
          responseLimitBytes = NativeDirectHttpLimits.HISTORY_BYTES,
        ),
        historiesTerminal = false,
      ),
    )
    fakeSession.historyNexts.add(
      NativeDirectHistoryNext(
        request = NativeDirectRestRequest(
          requestToken = "history-page-two",
          method = "GET",
          requestTarget = "/v1/messages/${conversation.conversationId}?limit=25&cursor=opaque",
          body = byteArrayOf(),
          responseLimitBytes = NativeDirectHttpLimits.HISTORY_BYTES,
        ),
        historiesTerminal = false,
      ),
    )
    fakeSession.historyInstalls.add(
      NativeDirectHistoryProgress(NativeDirectHistoryOutcome.IN_PROGRESS, historiesTerminal = false),
    )
    fakeSession.historyInstalls.add(
      NativeDirectHistoryProgress(
        NativeDirectHistoryOutcome.CONVERSATION_REJECTED,
        historiesTerminal = true,
      ),
    )
    val directoryBody = "authenticated-directory".toByteArray()
    val firstHistoryBody = "encrypted-history-page-one".toByteArray()
    val secondHistoryBody = "rejected-history-page-two".toByteArray()
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)

      transport.completeNext(NativeDirectHttpResult.Success(directoryBody))
      awaitRuntimeIdle(runtime)
      assertTrue(directoryBody.all { it == 0.toByte() })
      assertEquals(NativeDirectDirectoryState.SYNCHRONIZED, runtime.snapshot().directDirectoryState)
      assertEquals(NativeDirectHistoryState.SYNCING, runtime.snapshot().directHistoryState)
      assertEquals(NativeSecureSyncState.SYNCING_HISTORY, runtime.snapshot().secureSyncState)
      assertFalse(runtime.snapshot().directoryReady)
      assertEquals(1, transport.pendingCount())
      assertEquals(NativeDirectHttpLimits.HISTORY_BYTES, transport.requests.last().responseLimitBytes)
      assertEquals(NativeDirectHttpMethod.GET, transport.requests.last().method)
      assertTrue(transport.requests.last().body.isEmpty())

      transport.completeNext(NativeDirectHttpResult.Success(firstHistoryBody))
      awaitRuntimeIdle(runtime)
      assertTrue(firstHistoryBody.all { it == 0.toByte() })
      assertEquals(NativeDirectHistoryState.SYNCING, runtime.snapshot().directHistoryState)
      assertEquals(1, transport.pendingCount())

      transport.completeNext(NativeDirectHttpResult.Success(secondHistoryBody))
      awaitRuntimeIdle(runtime)
      val terminal = runtime.snapshot()
      assertTrue(secondHistoryBody.all { it == 0.toByte() })
      assertEquals(NativeDirectHistoryState.SYNCHRONIZED, terminal.directHistoryState)
      assertEquals(NativeSecureSyncState.HISTORY_SYNCHRONIZED, terminal.secureSyncState)
      assertEquals(NativeConnectionState.CONNECTED, terminal.connectionState)
      assertFalse("stage 5 must wait for live FIFO replay", terminal.directoryReady)
      assertEquals(2, fakeSession.historyInstalledResponseCopies.size)
      assertTrue(fakeSession.liveBufferPumpCount >= 5)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun terminalLiveEpochRejectsInFlightHttpBeforeDirectoryMutationAndWipesBody() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val response = "directory-response-that-must-not-install".toByteArray()
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)
      assertEquals(1, transport.pendingCount())

      fakeSession.failLiveBufferPump = true
      transport.completeNext(NativeDirectHttpResult.Success(response))
      awaitRuntimeIdle(runtime)

      assertTrue(response.all { it == 0.toByte() })
      assertTrue(fakeSession.installedResponseCopies.isEmpty())
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertEquals(NativeDirectDirectoryState.ERROR, runtime.snapshot().directDirectoryState)
      assertFalse(runtime.snapshot().directoryReady)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun contradictoryInProgressTerminalHistoryFailsClosedAndWipesBody() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    fakeSession.historyNexts.add(
      NativeDirectHistoryNext(
        request = NativeDirectRestRequest(
          requestToken = "history-contradictory-progress",
          method = "GET",
          requestTarget = "/v1/messages/550e8400-e29b-41d4-a716-446655440010?limit=25",
          body = byteArrayOf(),
          responseLimitBytes = NativeDirectHttpLimits.HISTORY_BYTES,
        ),
        historiesTerminal = false,
      ),
    )
    fakeSession.historyInstalls.add(
      NativeDirectHistoryProgress(
        NativeDirectHistoryOutcome.IN_PROGRESS,
        historiesTerminal = true,
      ),
    )
    val directoryBody = "directory-before-contradiction".toByteArray()
    val historyBody = "history-with-contradictory-progress".toByteArray()
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(NativeDirectHttpResult.Success(directoryBody))
      awaitRuntimeIdle(runtime)
      assertEquals(NativeDirectHistoryState.SYNCING, runtime.snapshot().directHistoryState)

      transport.completeNext(NativeDirectHttpResult.Success(historyBody))
      awaitRuntimeIdle(runtime)
      val failed = runtime.snapshot()
      assertTrue(historyBody.all { it == 0.toByte() })
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertEquals(NativeDirectHistoryState.ERROR, failed.directHistoryState)
      assertEquals(NativeSecureSyncState.ERROR, failed.secureSyncState)
      assertFalse(failed.directoryReady)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundRevokesHistoryRequestAndLateCallbackOnlyWipesItsBody() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    fakeSession.historyNexts.add(
      NativeDirectHistoryNext(
        request = NativeDirectRestRequest(
          requestToken = "history-late-callback",
          method = "GET",
          requestTarget = "/v1/messages/550e8400-e29b-41d4-a716-446655440010?limit=25",
          body = byteArrayOf(),
          responseLimitBytes = NativeDirectHttpLimits.HISTORY_BYTES,
        ),
        historiesTerminal = false,
      ),
    )
    val directoryBody = "directory-before-background".toByteArray()
    val lateHistoryBody = "late-history-after-background".toByteArray()
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(NativeDirectHttpResult.Success(directoryBody))
      awaitRuntimeIdle(runtime)
      assertEquals(NativeDirectHistoryState.SYNCING, runtime.snapshot().directHistoryState)
      val historyCall = transport.calls.last()
      assertTrue(historyCall.started.get())

      runtime.lockForBackground()
      assertTrue(historyCall.cancelled.get())
      transport.completeNext(NativeDirectHttpResult.Success(lateHistoryBody))
      awaitRuntimeIdle(runtime)

      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
      assertTrue(lateHistoryBody.all { it == 0.toByte() })
      assertTrue(fakeSession.historyInstalledResponseCopies.isEmpty())
      assertTrue(fakeSession.directLeaseCancellations >= 1)
      assertFalse(runtime.snapshot().directoryReady)
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
      completeOwnPreKeyBootstrap(runtime, transport)
      val pendingCall = transport.calls.last()
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
      assertEquals(NativeOwnPreKeyState.ERROR, failed.ownPreKeyState)
      assertEquals(NativeSecureSyncState.ERROR, failed.secureSyncState)
      assertNull(failed.binding)
      assertTrue(failed.directConversations.isEmpty())
      assertFalse(failed.directoryReady)
      assertEquals(1, fakeSession.directLeaseCancellations)

      runtime.connect("https://access.example")
      val retried = runtime.snapshot()
      assertEquals(NativeConnectionState.CONNECTED, retried.connectionState)
      assertEquals(NativeDirectDirectoryState.IDLE, retried.directDirectoryState)
      assertEquals(NativeOwnPreKeyState.CHECKING, retried.ownPreKeyState)
      assertEquals(NativeSecureSyncState.PUBLISHING_KEYS, retried.secureSyncState)
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
      assertEquals("Unable to complete the secure Direct bootstrap", error.message)
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
      completeOwnPreKeyBootstrap(runtime, transport)
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
  fun ownPreKeyCountAndExactUploadCompleteBeforeTheFirstDirectoryRequest() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    try {
      runtime.openSession()
      runtime.connect("https://access.example")

      assertEquals(0, fakeSession.directoryRequestCount)
      assertEquals(NativeOwnPreKeyState.CHECKING, runtime.snapshot().ownPreKeyState)
      assertEquals(NativeSecureSyncState.PUBLISHING_KEYS, runtime.snapshot().secureSyncState)
      val count = transport.requests.single()
      assertEquals(NativeDirectHttpMethod.GET, count.method)
      assertTrue(count.body.isEmpty())
      assertEquals("GET", fakeSession.signedRequestCopies.single().method)
      assertTrue(fakeSession.signedRequestCopies.single().body.isEmpty())

      val countResponse = "{\"device_id\":\"test-device\",\"remaining\":0}".toByteArray()
      transport.completeNext(NativeDirectHttpResult.Success(countResponse))
      awaitRuntimeIdle(runtime)
      assertTrue(countResponse.all { it == 0.toByte() })

      assertEquals(0, fakeSession.directoryRequestCount)
      assertEquals(NativeOwnPreKeyState.PUBLISHING, runtime.snapshot().ownPreKeyState)
      val upload = transport.requests.last()
      val uploadedBody = transport.capturedBodies.last()
      assertEquals(NativeDirectHttpMethod.POST, upload.method)
      assertEquals("/v1/prekeys", upload.requestTarget)
      assertArrayEquals(OWN_PREKEY_PUBLICATION_BODY, uploadedBody)
      assertTrue(
        "runtime wire copy must be wiped after transport snapshots it",
        upload.body.all { it == 0.toByte() },
      )
      assertEquals("POST", fakeSession.signedRequestCopies.last().method)
      assertArrayEquals(uploadedBody, fakeSession.signedRequestCopies.last().body)

      val uploadResponse = "{\"stored\":21,\"device_id\":\"test-device\"}".toByteArray()
      transport.completeNext(NativeDirectHttpResult.Success(uploadResponse))
      awaitRuntimeIdle(runtime)
      assertTrue(uploadResponse.all { it == 0.toByte() })

      assertEquals(1, fakeSession.directoryRequestCount)
      assertEquals(NativeOwnPreKeyState.PUBLISHED, runtime.snapshot().ownPreKeyState)
      assertEquals(NativeDirectDirectoryState.SYNCING, runtime.snapshot().directDirectoryState)
      assertEquals(NativeSecureSyncState.SYNCING_DIRECTORY, runtime.snapshot().secureSyncState)
      assertEquals(NativeDirectHttpMethod.GET, transport.requests.last().method)
      assertTrue(transport.requests.last().requestTarget.startsWith("/v1/conversations?"))
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun staleOwnPreKeyCallbackAfterBackgroundLockCannotInstallOrStartDirectory() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val lateCount = "late-count-response".toByteArray()
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      val pendingCall = transport.calls.single()

      runtime.lockForBackground()
      assertTrue(pendingCall.cancelled.get())
      transport.completeNext(NativeDirectHttpResult.Success(lateCount))
      awaitRuntimeIdle(runtime)

      assertTrue(lateCount.all { it == 0.toByte() })
      assertEquals(0, fakeSession.ownPreKeyInstallCount)
      assertEquals(0, fakeSession.directoryRequestCount)
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
      assertEquals(NativeOwnPreKeyState.IDLE, runtime.snapshot().ownPreKeyState)
      assertEquals(NativeSecureSyncState.IDLE, runtime.snapshot().secureSyncState)
    } finally {
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundDuringOwnPreKeyCallCreationCancelsItBeforeStart() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val callCreated = CountDownLatch(1)
    val releaseCreation = CountDownLatch(1)
    val blockFirstCall = AtomicBoolean(true)
    val transport = ControllableDirectTransport {
      if (blockFirstCall.compareAndSet(true, false)) {
        callCreated.countDown()
        check(releaseCreation.await(5, TimeUnit.SECONDS)) { "call creation barrier timed out" }
      }
    }
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    runtime.openSession()
    val connectError = AtomicReference<Throwable?>()
    val connector = thread(name = "own-prekey-create-before-background") {
      try {
        runtime.connect("https://access.example")
      } catch (error: Throwable) {
        connectError.set(error)
      }
    }
    try {
      assertTrue("own-prekey call was not created", callCreated.await(5, TimeUnit.SECONDS))
      val unstarted = transport.calls.single()
      assertFalse(unstarted.started.get())
      assertTrue(transport.requests.isEmpty())

      runtime.lockForBackground()
      releaseCreation.countDown()
      connector.join(5_000)
      assertFalse("stale connector did not finish", connector.isAlive)
      awaitRuntimeIdle(runtime)

      assertNull(connectError.get())
      assertTrue("detached unstarted call must be cancelled", unstarted.cancelled.get())
      assertFalse("cancelled own-prekey call must never start", unstarted.started.get())
      assertTrue("cancelled own-prekey call must never reach transport", transport.requests.isEmpty())
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
    } finally {
      releaseCreation.countDown()
      connector.join(5_000)
      executor.shutdownNow()
    }
  }

  @Test
  fun reconnectDuringDirectoryCallCreationCancelsItBeforeStart() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val directoryCallCreated = CountDownLatch(1)
    val releaseDirectoryCreation = CountDownLatch(1)
    val createdCalls = AtomicInteger(0)
    val transport = ControllableDirectTransport {
      if (createdCalls.incrementAndGet() == 3) {
        directoryCallCreated.countDown()
        check(releaseDirectoryCreation.await(5, TimeUnit.SECONDS)) {
          "directory call creation barrier timed out"
        }
      }
    }
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      transport.completeNext(
        NativeDirectHttpResult.Success("{\"device_id\":\"test-device\",\"remaining\":0}".toByteArray()),
      )
      awaitRuntimeIdle(runtime)
      transport.completeNext(
        NativeDirectHttpResult.Success("{\"stored\":21,\"device_id\":\"test-device\"}".toByteArray()),
      )
      assertTrue(
        "directory call was not created",
        directoryCallCreated.await(5, TimeUnit.SECONDS),
      )
      val staleDirectoryCall = transport.calls[2]
      assertFalse(staleDirectoryCall.started.get())

      runtime.connect("https://access.example")
      assertEquals(1, fakeSession.directLeaseCancellations)
      releaseDirectoryCreation.countDown()
      awaitRuntimeIdle(runtime)

      assertTrue("superseded directory call must be cancelled", staleDirectoryCall.cancelled.get())
      assertFalse("superseded directory call must never start", staleDirectoryCall.started.get())
      assertTrue(
        "superseded directory call must never reach transport",
        transport.requests.none { request -> request.requestTarget.startsWith("/v1/conversations") },
      )
      assertEquals(1, transport.pendingCount())
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
      assertEquals(NativeOwnPreKeyState.CHECKING, runtime.snapshot().ownPreKeyState)
    } finally {
      releaseDirectoryCreation.countDown()
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun staleOwnPreKeyCallbackFromSupersededConnectionCannotAffectTheNewGeneration() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val staleCount = "stale-generation-count".toByteArray()
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      val supersededCall = transport.calls.single()

      runtime.connect("https://access.example")
      assertTrue(supersededCall.cancelled.get())
      assertEquals(2, transport.pendingCount())
      assertEquals(1, fakeSession.directLeaseCancellations)

      transport.completeNext(NativeDirectHttpResult.Success(staleCount))
      awaitRuntimeIdle(runtime)

      assertTrue(staleCount.all { it == 0.toByte() })
      assertEquals(0, fakeSession.ownPreKeyInstallCount)
      assertEquals(0, fakeSession.directoryRequestCount)
      assertEquals(1, transport.pendingCount())
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
      assertEquals(NativeOwnPreKeyState.CHECKING, runtime.snapshot().ownPreKeyState)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun failedOwnPreKeyUploadRetriesTheSameDurableBodyOnAFreshConnection() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    var firstUploadBody = ByteArray(0)
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      transport.completeNext(
        NativeDirectHttpResult.Success("{\"device_id\":\"test-device\",\"remaining\":0}".toByteArray()),
      )
      awaitRuntimeIdle(runtime)
      firstUploadBody = transport.capturedBodies.last().copyOf()
      assertEquals(NativeDirectHttpMethod.POST, transport.requests.last().method)

      transport.completeNext(NativeDirectHttpResult.Failure(NativeDirectHttpFailure.NETWORK))
      awaitRuntimeIdle(runtime)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertEquals(0, fakeSession.directoryRequestCount)

      runtime.connect("https://access.example")
      assertEquals(NativeOwnPreKeyState.PUBLISHING, runtime.snapshot().ownPreKeyState)
      assertEquals(NativeDirectHttpMethod.POST, transport.requests.last().method)
      assertArrayEquals(firstUploadBody, transport.capturedBodies.last())
      assertArrayEquals(firstUploadBody, fakeSession.signedRequestCopies.last().body)

      transport.completeNext(
        NativeDirectHttpResult.Success("{\"stored\":21,\"device_id\":\"test-device\"}".toByteArray()),
      )
      awaitRuntimeIdle(runtime)
      assertEquals(1, fakeSession.directoryRequestCount)
      assertEquals(NativeOwnPreKeyState.PUBLISHED, runtime.snapshot().ownPreKeyState)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
    } finally {
      firstUploadBody.fill(0)
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun generatedDirectCapabilitiesMapToRedactingNativeOnlyDtos() {
    val leaseToken = "lease-capability-that-must-not-be-logged"
    val requestToken = "request-capability-that-must-not-be-logged"
    val requestTarget = "/v1/prekeys/peer-identity-key-hex-must-not-be-logged"
    val requestBody = "public-prekey-body-must-not-be-logged".toByteArray()
    val signatureValue = "signed-header-that-must-not-be-logged"

    val lease = MobileDirectSyncLease(
      token = leaseToken,
      canonicalServerOrigin = "https://chat.example:443",
      userId = USER_ID,
    ).toNativeDirectSyncLease()
    val generatedRequest = MobileDirectRestRequest(
      requestToken = requestToken,
      method = "POST",
      requestTarget = requestTarget,
      body = requestBody.copyOf(),
      responseLimitBytes = NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES.toUInt(),
    )
    val request = generatedRequest.toNativeDirectRestRequest()
    val signature = RestSignatureData(
      userId = USER_ID,
      timestampMs = "1712345678901",
      signatureBase64 = signatureValue,
    ).toNativeRestSignature()

    assertEquals(leaseToken, lease.leaseToken)
    assertEquals("https://chat.example:443", lease.canonicalServerOrigin)
    assertEquals(USER_ID, lease.userId)
    assertEquals(requestToken, request.requestToken)
    assertEquals("POST", request.method)
    assertEquals(requestTarget, request.requestTarget)
    assertArrayEquals(requestBody, request.body)
    assertTrue(generatedRequest.body.all { it == 0.toByte() })
    assertEquals(NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES, request.responseLimitBytes)
    assertEquals(USER_ID, signature.userId)
    assertEquals("1712345678901", signature.timestampMs)
    assertEquals(signatureValue, signature.signatureBase64)
    assertFalse(lease.toString().contains(leaseToken))
    assertFalse(request.toString().contains(requestToken))
    assertFalse(request.toString().contains(requestTarget))
    assertFalse(request.toString().contains(String(requestBody)))
    assertFalse(signature.toString().contains(signatureValue))
  }

  @Test
  fun generatedHistoryBridgeMapsOnlyTypedCoarseProgress() {
    val request = MobileDirectRestRequest(
      requestToken = "history-capability",
      method = "GET",
      requestTarget = "/v1/messages/550e8400-e29b-41d4-a716-446655440010?limit=25",
      body = byteArrayOf(),
      responseLimitBytes = NativeDirectHttpLimits.HISTORY_BYTES.toUInt(),
    )
    val next = MobileDirectHistoryNext(request, historiesTerminal = false).toNativeDirectHistoryNext()
    assertFalse(next.historiesTerminal)
    assertEquals(NativeDirectHttpLimits.HISTORY_BYTES, next.request?.responseLimitBytes)

    val expected = listOf(
      MobileDirectHistoryOutcome.IN_PROGRESS to NativeDirectHistoryOutcome.IN_PROGRESS,
      MobileDirectHistoryOutcome.COMPLETE to NativeDirectHistoryOutcome.COMPLETE,
      MobileDirectHistoryOutcome.INCOMPLETE_SELF_HISTORY to
        NativeDirectHistoryOutcome.INCOMPLETE_SELF_HISTORY,
      MobileDirectHistoryOutcome.CONVERSATION_REJECTED to
        NativeDirectHistoryOutcome.CONVERSATION_REJECTED,
      MobileDirectHistoryOutcome.STORAGE_UNCERTAIN to NativeDirectHistoryOutcome.STORAGE_UNCERTAIN,
    )
    expected.forEach { (generated, native) ->
      assertEquals(
        native,
        MobileDirectHistoryProgress(generated, historiesTerminal = false)
          .toNativeDirectHistoryProgress()
          .outcome,
      )
    }
    val live = MobileDirectLiveBufferProgress(17u, historySynchronized = true)
      .toNativeDirectLiveBufferProgress()
    assertEquals(17L, live.bufferedEvents)
    assertTrue(live.historySynchronized)
  }

  @Test
  fun generatedDirectMessageProjectionMapsOnlyTheMinimalUiContract() {
    val nativeView = NativeDirectMessageView(
      messageId = "30000000-0000-4000-8000-000000000001",
      text = "authenticated preview",
      timestampMs = 1_700_000_000_123,
      direction = NativeDirectMessageDirection.INCOMING,
      delivery = NativeDirectMessageDelivery.SENT,
    )
    val nativeProjection = NativeDirectMessageProjection(
      NativeDirectMessageProjectionAvailability.AVAILABLE,
      listOf(nativeView),
    )
    assertFalse(nativeView.toString().contains("authenticated preview"))
    assertFalse(nativeProjection.toString().contains("authenticated preview"))
    assertEquals(
      setOf("messageId", "text", "timestampMs", "direction", "delivery"),
      NativeDirectMessageView::class.java.declaredFields.map { it.name }.toSet(),
    )
    val generatedFields = MobileDirectMessageData::class.java.declaredFields.map { it.name }.toSet()
    assertFalse(generatedFields.contains("messageId"))
    assertFalse(generatedFields.contains("text"))

    val denied = MobileDirectMessageProjection(
      availability = MobileDirectMessageProjectionAvailability.UNAVAILABLE,
      messages = emptyList(),
    ).toNativeDirectMessageProjection()
    assertEquals(NativeDirectMessageProjectionAvailability.UNAVAILABLE, denied.availability)
    assertTrue(denied.messages.isEmpty())

    class TestHandle(
      val value: String,
      val fail: Boolean = false,
    ) : AutoCloseable {
      var closed = false
      override fun close() {
        closed = true
      }
    }

    val successfulHandles = listOf(TestHandle("one"), TestHandle("two"))
    assertEquals(
      listOf("one", "two"),
      mapAndCloseAllNativeHandles(successfulHandles) { it.value },
    )
    assertTrue(successfulHandles.all { it.closed })

    val failingHandles = listOf(TestHandle("one"), TestHandle("two", fail = true), TestHandle("three"))
    assertThrows(IllegalStateException::class.java) {
      mapAndCloseAllNativeHandles(failingHandles) { handle ->
        check(!handle.fail) { "synthetic getter failure" }
        handle.value
      }
    }
    assertTrue(failingHandles.all { it.closed })
  }

  @Test
  fun directProjectionStructuralGuardEnforcesUtf8RowAndAggregateBudgets() {
    fun message(index: Int, text: String) = NativeDirectMessageView(
      messageId = "30000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}",
      text = text,
      timestampMs = 1_700_000_000_000L + index,
      direction = NativeDirectMessageDirection.INCOMING,
      delivery = NativeDirectMessageDelivery.SENT,
    )

    fun projection(messages: List<NativeDirectMessageView>) = NativeDirectMessageProjection(
      NativeDirectMessageProjectionAvailability.AVAILABLE,
      messages,
    )

    val exactRow = "a".repeat(32 * 1024)
    assertTrue(projection(listOf(message(1, exactRow))).isStructurallySafe())
    assertFalse(projection(listOf(message(1, "$exactRow+"))).isStructurallySafe())

    val exactTotal = (1..32).map { index -> message(index, exactRow) }
    assertTrue(projection(exactTotal).isStructurallySafe())
    assertFalse(projection(exactTotal + message(33, "x")).isStructurallySafe())

    val fourByteScalar = "\uD83E\uDD80"
    val exactMultibyteRow = fourByteScalar.repeat((32 * 1024) / 4)
    assertTrue(projection(listOf(message(1, exactMultibyteRow))).isStructurallySafe())
    assertFalse(
      projection(listOf(message(1, exactMultibyteRow + fourByteScalar))).isStructurallySafe(),
    )
    assertFalse(projection(listOf(message(1, ""))).isStructurallySafe())
    assertFalse(projection(listOf(message(1, "\uD800"))).isStructurallySafe())
    assertFalse(
      NativeDirectMessageProjection(
        NativeDirectMessageProjectionAvailability.UNAVAILABLE,
        listOf(message(1, "must remain opaque")),
      ).isStructurallySafe(),
    )
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

  private fun publishDirectMessagesForTest(
    runtime: VeilMobileRuntime,
    conversationId: String,
  ): NativeDirectMessageProjection {
    val published = AtomicReference<NativeDirectMessageProjection>()
    var publicationCount = 0
    runtime.publishDirectMessages(conversationId) { projection ->
      publicationCount += 1
      published.set(projection)
    }
    assertEquals(1, publicationCount)
    return checkNotNull(published.get())
  }

  private fun forceDirectoryReadyForProjectionTest(runtime: VeilMobileRuntime) {
    val field = VeilMobileRuntime::class.java.getDeclaredField("directoryReady")
    field.isAccessible = true
    field.setBoolean(runtime, true)
    assertTrue(runtime.snapshot().directoryReady)
  }

  /** Complete the mandatory count -> exact publication ACK barrier. */
  private fun completeOwnPreKeyBootstrap(
    runtime: VeilMobileRuntime,
    transport: ControllableDirectTransport,
  ) {
    val count = transport.requests.last()
    assertEquals(NativeDirectHttpMethod.GET, count.method)
    assertEquals(NativeDirectHttpLimits.OWN_PREKEY_COUNT_BYTES, count.responseLimitBytes)
    assertTrue(count.body.isEmpty())
    transport.completeNext(
      NativeDirectHttpResult.Success("{\"device_id\":\"test-device\",\"remaining\":0}".toByteArray()),
    )
    awaitRuntimeIdle(runtime)

    val upload = transport.requests.last()
    assertEquals(NativeDirectHttpMethod.POST, upload.method)
    assertEquals("/v1/prekeys", upload.requestTarget)
    assertEquals(NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES, upload.responseLimitBytes)
    assertTrue(transport.capturedBodies.last().isNotEmpty())
    transport.completeNext(
      NativeDirectHttpResult.Success("{\"stored\":21,\"device_id\":\"test-device\"}".toByteArray()),
    )
    awaitRuntimeIdle(runtime)
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
    var historyRequestCount = 0
    var liveBufferPumpCount = 0
    var directProjectionCount = 0
    @Volatile var directProjection = NativeDirectMessageProjection(
      NativeDirectMessageProjectionAvailability.UNAVAILABLE,
      emptyList(),
    )
    @Volatile var directProjectionEntered: CountDownLatch? = null
    @Volatile var directProjectionRelease: CountDownLatch? = null
    @Volatile var directProjectionFailure: Throwable? = null
    var failLiveBufferPump = false
    var historySynchronized = false
    var ownPreKeyRequestCount = 0
    var ownPreKeyInstallCount = 0
    var ownPreKeyPendingPublication: ByteArray? = null
    val ownPreKeyInstalledResponseCopies = CopyOnWriteArrayList<ByteArray>()
    val signedRequestCopies = CopyOnWriteArrayList<SignedRequestCopy>()
    private val preparedRequests = ConcurrentHashMap<String, NativeDirectRestRequest>()
    val directoryInstalls = ArrayDeque<NativeDirectDirectoryInstall>().apply {
      add(NativeDirectDirectoryInstall(emptyList(), directoryComplete = true))
    }
    val installedResponseCopies = CopyOnWriteArrayList<ByteArray>()
    val historyInstalledResponseCopies = CopyOnWriteArrayList<ByteArray>()
    val historyNexts = ArrayDeque<NativeDirectHistoryNext>()
    val historyInstalls = ArrayDeque<NativeDirectHistoryProgress>()
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

    override fun beginDirectSync(): NativeDirectSyncLease {
      historySynchronized = false
      return NativeDirectSyncLease(
        leaseToken = "test-direct-lease",
        canonicalServerOrigin = checkNotNull(canonicalOrigin),
        userId = directLeaseUserOverride ?: USER_ID,
      )
    }

    override fun prepareOwnPreKeyRequest(leaseToken: String): NativeDirectRestRequest {
      ownPreKeyRequestCount += 1
      val pendingPublication = ownPreKeyPendingPublication
      val prepared = if (pendingPublication == null) {
        NativeDirectRestRequest(
          requestToken = "test-own-prekey-count-$ownPreKeyRequestCount",
          method = "GET",
          requestTarget = "/v1/prekeys/${"ab".repeat(32)}/count",
          body = byteArrayOf(),
          responseLimitBytes = NativeDirectHttpLimits.OWN_PREKEY_COUNT_BYTES,
        )
      } else {
        NativeDirectRestRequest(
          requestToken = "test-own-prekey-upload-$ownPreKeyRequestCount",
          method = "POST",
          requestTarget = "/v1/prekeys",
          body = pendingPublication.copyOf(),
          responseLimitBytes = NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES,
        )
      }
      return rememberPreparedRequest(prepared)
    }

    override fun installOwnPreKeyResponse(
      leaseToken: String,
      requestToken: String,
      response: ByteArray,
    ): NativeDirectOwnPreKeyProgress {
      ownPreKeyInstallCount += 1
      ownPreKeyInstalledResponseCopies.add(response.copyOf())
      preparedRequests.remove(requestToken)?.body?.fill(0)
      return if (requestToken.startsWith("test-own-prekey-count-")) {
        check(ownPreKeyPendingPublication == null)
        ownPreKeyPendingPublication = OWN_PREKEY_PUBLICATION_BODY.copyOf()
        NativeDirectOwnPreKeyProgress(publicationComplete = false)
      } else {
        check(requestToken.startsWith("test-own-prekey-upload-"))
        check(ownPreKeyPendingPublication != null)
        ownPreKeyPendingPublication?.fill(0)
        ownPreKeyPendingPublication = null
        NativeDirectOwnPreKeyProgress(publicationComplete = true)
      }
    }

    override fun prepareDirectDirectoryRequest(leaseToken: String): NativeDirectRestRequest {
      directoryRequestCount += 1
      return rememberPreparedRequest(NativeDirectRestRequest(
        requestToken = "test-directory-request-$directoryRequestCount",
        method = "GET",
        requestTarget = if (directoryRequestCount == 1) {
          "/v1/conversations?limit=100"
        } else {
          "/v1/conversations?cursor=cursor-$directoryRequestCount&limit=100"
        },
        body = byteArrayOf(),
        responseLimitBytes = NativeDirectHttpLimits.DIRECTORY_BYTES,
      ))
    }

    override fun installDirectDirectoryPage(
      leaseToken: String,
      requestToken: String,
      response: ByteArray,
    ): NativeDirectDirectoryInstall {
      installedResponseCopies.add(response.copyOf())
      preparedRequests.remove(requestToken)?.body?.fill(0)
      return directoryInstalls.removeFirst()
    }

    override fun prepareNextDirectHistoryRequest(leaseToken: String): NativeDirectHistoryNext {
      historyRequestCount += 1
      val next = if (historyNexts.isEmpty()) {
        NativeDirectHistoryNext(request = null, historiesTerminal = true)
      } else {
        historyNexts.removeFirst()
      }
      if (next.historiesTerminal) historySynchronized = true
      next.request?.let(::rememberPreparedRequest)
      return next
    }

    override fun installDirectHistoryResponse(
      leaseToken: String,
      requestToken: String,
      response: ByteArray,
    ): NativeDirectHistoryProgress {
      historyInstalledResponseCopies.add(response.copyOf())
      preparedRequests.remove(requestToken)?.body?.fill(0)
      val progress = if (historyInstalls.isEmpty()) {
        NativeDirectHistoryProgress(NativeDirectHistoryOutcome.COMPLETE, historiesTerminal = true)
      } else {
        historyInstalls.removeFirst()
      }
      if (progress.historiesTerminal) historySynchronized = true
      return progress
    }

    override fun bufferDirectLiveEventsDuringSync(leaseToken: String): NativeDirectLiveBufferProgress {
      liveBufferPumpCount += 1
      if (failLiveBufferPump) throw IllegalStateException("synthetic terminal live buffer")
      return NativeDirectLiveBufferProgress(
        bufferedEvents = 0,
        historySynchronized = historySynchronized,
      )
    }

    override fun projectDirectMessages(conversationId: String): NativeDirectMessageProjection {
      directProjectionCount += 1
      directProjectionEntered?.countDown()
      directProjectionRelease?.let { release ->
        check(release.await(5, TimeUnit.SECONDS)) { "synthetic Direct projection timed out" }
      }
      directProjectionFailure?.let { throw it }
      return directProjection
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
      preparedRequests.values.forEach { request -> request.body.fill(0) }
      preparedRequests.clear()
      signedRequestCopies.forEach { request -> request.body.fill(0) }
    }

    override fun signDirectRestRequest(
      leaseToken: String,
      requestToken: String,
    ): NativeRestSignature {
      check(leaseToken == "test-direct-lease")
      val prepared = checkNotNull(preparedRequests[requestToken])
      signedRequestCopies.add(
        SignedRequestCopy(prepared.method, prepared.requestTarget, prepared.body.copyOf()),
      )
      return NativeRestSignature(
        userId = USER_ID,
        timestampMs = "1712345678901",
        signatureBase64 = Base64.getEncoder().encodeToString(ByteArray(64)),
      )
    }

    override fun disconnect() {
      lifecycleEvents.add("disconnect")
    }

    override fun close() {
      closedDuringConnect.set(inConnect.get())
      closed = true
      lifecycleEvents.add("close")
      lastAccessPass?.fill(0)
      ownPreKeyPendingPublication?.fill(0)
      preparedRequests.values.forEach { request -> request.body.fill(0) }
      preparedRequests.clear()
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

    private fun rememberPreparedRequest(request: NativeDirectRestRequest): NativeDirectRestRequest {
      val retained = request.copy(body = request.body.copyOf())
      check(preparedRequests.putIfAbsent(request.requestToken, retained) == null)
      return request
    }

    data class SignedRequestCopy(
      val method: String,
      val requestTarget: String,
      val body: ByteArray,
    )
  }

  private class PassiveDirectTransport : NativeDirectHttpExecutor {
    override fun createCall(
      request: NativeDirectHttpRequest,
      callback: NativeDirectHttpCallback,
    ): NativeDirectHttpCall = object : NativeDirectHttpCall {
      override fun start() = Unit

      override fun cancel() = Unit
    }
  }

  private class ControllableDirectTransport(
    private val onCallCreated: ((TestDirectHttpCall) -> Unit)? = null,
  ) : NativeDirectHttpExecutor {
    private data class Pending(
      val callback: NativeDirectHttpCallback,
      val call: TestDirectHttpCall,
    )

    private val pending = ArrayDeque<Pending>()
    val requests = CopyOnWriteArrayList<NativeDirectHttpRequest>()
    val capturedBodies = CopyOnWriteArrayList<ByteArray>()
    val calls = CopyOnWriteArrayList<TestDirectHttpCall>()

    override fun createCall(
      request: NativeDirectHttpRequest,
      callback: NativeDirectHttpCallback,
    ): NativeDirectHttpCall {
      val exactBody = request.body.copyOf()
      lateinit var call: TestDirectHttpCall
      call = TestDirectHttpCall {
        synchronized(this) {
          requests.add(request)
          pending.add(Pending(callback, call))
        }
      }
      synchronized(this) {
        capturedBodies.add(exactBody)
        calls.add(call)
      }
      onCallCreated?.invoke(call)
      return call
    }

    fun pendingCount(): Int = synchronized(this) { pending.size }

    fun completeNext(result: NativeDirectHttpResult) {
      val selected = synchronized(this) { pending.removeFirst() }
      // Deliberately permit a completion after cancel to model a callback that
      // already won the transport's terminal CAS before lifecycle detachment.
      selected.callback.onComplete(result)
    }

    class TestDirectHttpCall(
      private val onStart: () -> Unit,
    ) : NativeDirectHttpCall {
      val cancelled = AtomicBoolean(false)
      val started = AtomicBoolean(false)

      override fun start() {
        synchronized(this) {
          if (cancelled.get() || !started.compareAndSet(false, true)) return
          onStart()
        }
      }

      override fun cancel() {
        synchronized(this) {
          cancelled.set(true)
        }
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
    private val OWN_PREKEY_PUBLICATION_BODY =
      "{\"device_id\":\"00112233445566778899aabbccddeeff\",\"signed_prekey\":{}}".toByteArray()
    private const val USER_ID = "550e8400-e29b-41d4-a716-446655440001"
  }
}
