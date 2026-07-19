package io.veil.mobile.runtime

import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
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
import uniffi.veil_ffi.MobileDirectLiveReplayProgress
import uniffi.veil_ffi.MobileDirectMessageData
import uniffi.veil_ffi.MobileDirectMessageProjection
import uniffi.veil_ffi.MobileDirectMessageProjectionAvailability
import uniffi.veil_ffi.MobileDirectPreKeyResult
import uniffi.veil_ffi.MobileDirectRestRequest
import uniffi.veil_ffi.MobileDirectSendReadiness
import uniffi.veil_ffi.MobileDirectSyncLease
import uniffi.veil_ffi.MobileRetryableReason
import uniffi.veil_ffi.RestSignatureData
import uniffi.veil_ffi.VeilException

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
  fun openSessionWithoutStoredTargetStaysDisconnectedAndNeverTouchesNetwork() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val fakeSession = FakeSession()
    val runtime = runtime(executor, fakeSession)
    try {
      val opened = runtime.openSession()

      assertEquals(NativeSessionState.OPEN, opened.sessionState)
      assertEquals(NativeConnectionState.DISCONNECTED, opened.connectionState)
      assertNull(opened.binding)
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(1, fakeSession.storedReconnectTargetLoadCount)
      assertEquals(0, fakeSession.plainConnectCount)
      assertEquals(0, fakeSession.accessPassConnectCount)
      assertEquals(0, executor.immediateScheduleCount())
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun storedTargetCreatesOneImmediatePlainReconnectWithoutPublishingABindingEarly() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://resume.example:443",
        expectedUserId = USER_ID,
      )
    }
    val runtime = runtime(executor, fakeSession)
    try {
      val opened = runtime.openSession()

      assertEquals(NativeSessionState.OPEN, opened.sessionState)
      assertEquals(NativeConnectionState.CONNECTING, opened.connectionState)
      assertNull(opened.binding)
      assertEquals(
        NativeReconnectPlanDebug(
          reason = null,
          failureOrdinal = null,
          delayMillis = 0L,
          stage = NativeReconnectStage.WAITING,
          trigger = NativeReconnectTrigger.STORED_TARGET,
        ),
        runtime.reconnectPlanForTesting(),
      )
      assertEquals(1, executor.immediateScheduleCount())
      assertEquals(0, fakeSession.plainConnectCount)
      assertEquals(0, fakeSession.accessPassConnectCount)

      // Reopening the same installed SQLCipher handle cannot create another
      // stored-target owner or read native recovery state a second time.
      assertEquals(NativeConnectionState.CONNECTING, runtime.openSession().connectionState)
      assertEquals(1, fakeSession.storedReconnectTargetLoadCount)
      assertEquals(1, executor.immediateScheduleCount())

      executor.runCapturedImmediateTask()

      assertEquals(1, fakeSession.plainConnectCount)
      assertEquals(0, fakeSession.accessPassConnectCount)
      assertEquals("wss://resume.example:443/ws", fakeSession.websocketUrl)
      assertEquals("https://resume.example:443", fakeSession.canonicalOrigin)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
      assertEquals(USER_ID, runtime.snapshot().binding?.userId)
      assertEquals(1, fakeSession.directSyncBeginCount)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun pendingAccessPassSuppressesOldStoredTargetUntilTheExplicitPassAttempt() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://old.example:443",
        expectedUserId = USER_ID,
      )
    }
    val passStore = deterministicPassStore()
    val runtime = runtime(executor, fakeSession, passStore)
    val tokenBytes = ByteArray(32) { 0x6d.toByte() }
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes)
    try {
      assertTrue(runtime.consumeEnrollmentUri("https://new.example/enroll#invite=$token"))
      val pending = checkNotNull(runtime.snapshot().pendingAccessPass)

      val opened = runtime.openSession()
      assertEquals(NativeConnectionState.DISCONNECTED, opened.connectionState)
      assertNull(opened.binding)
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(0, executor.immediateScheduleCount())
      assertEquals(0, fakeSession.plainConnectCount)

      runtime.connectPendingAccessPass(pending.flowId)

      assertEquals(0, fakeSession.plainConnectCount)
      assertEquals(1, fakeSession.accessPassConnectCount)
      assertArrayEquals(tokenBytes, fakeSession.lastAccessPass)
      assertEquals("https://new.example:443", fakeSession.canonicalOrigin)
      assertNull(runtime.snapshot().pendingAccessPass)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun stagingPassAfterOpenCancelsQueuedStoredRecoveryBeforeOldOriginCanConnect() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://old.example:443",
        expectedUserId = USER_ID,
      )
    }
    val runtime = runtime(executor, fakeSession, deterministicPassStore())
    val tokenBytes = ByteArray(32) { 0x6e.toByte() }
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes)
    try {
      assertEquals(NativeConnectionState.CONNECTING, runtime.openSession().connectionState)
      assertTrue(runtime.consumeEnrollmentUri("https://new.example/enroll#invite=$token"))
      val pending = checkNotNull(runtime.snapshot().pendingAccessPass)

      assertEquals(NativeConnectionState.DISCONNECTED, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertNull(runtime.reconnectPlanForTesting())

      // FIFO contains the cancelled stored plan followed by its exact-owner
      // transport teardown. Neither may authenticate the old origin.
      executor.runCapturedImmediateTask()
      executor.runCapturedImmediateTask()
      assertEquals(0, fakeSession.plainConnectCount)
      assertEquals(0, fakeSession.accessPassConnectCount)

      runtime.connectPendingAccessPass(pending.flowId)
      assertEquals(0, fakeSession.plainConnectCount)
      assertEquals(1, fakeSession.accessPassConnectCount)
      assertArrayEquals(tokenBytes, fakeSession.lastAccessPass)
      assertEquals("https://new.example:443", runtime.snapshot().binding?.canonicalServerOrigin)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun stagingPassDuringStoredTargetLoadSuppressesRecoveryAtSessionInstall() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val loadEntered = CountDownLatch(1)
    val loadRelease = CountDownLatch(1)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://old.example:443",
        expectedUserId = USER_ID,
      )
      storedReconnectTargetLoadEntered = loadEntered
      storedReconnectTargetLoadRelease = loadRelease
    }
    val runtime = runtime(executor, fakeSession, deterministicPassStore())
    val opened = AtomicReference<VeilMobileRuntimeSnapshot>()
    val openError = AtomicReference<Throwable?>()
    val opener = thread(name = "stored-target-pass-race") {
      try {
        opened.set(runtime.openSession())
      } catch (error: Throwable) {
        openError.set(error)
      }
    }
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 0x6f })
    try {
      assertTrue("stored target load did not begin", loadEntered.await(5, TimeUnit.SECONDS))
      assertTrue(runtime.consumeEnrollmentUri("https://new.example/enroll#invite=$token"))
      loadRelease.countDown()
      opener.join(TimeUnit.SECONDS.toMillis(5))

      assertFalse("stored target opener did not finish", opener.isAlive)
      assertNull(openError.get())
      assertEquals(NativeSessionState.OPEN, opened.get()?.sessionState)
      assertEquals(NativeConnectionState.DISCONNECTED, opened.get()?.connectionState)
      assertNull(opened.get()?.binding)
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(0, executor.immediateScheduleCount())
      assertEquals(0, fakeSession.plainConnectCount)
      assertTrue(runtime.snapshot().pendingAccessPass != null)
    } finally {
      loadRelease.countDown()
      opener.join(TimeUnit.SECONDS.toMillis(5))
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun stagingPassCancelsConnectingStoredRecoveryEvenIfAdapterReturnsLateSuccess() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://old.example:443",
        expectedUserId = USER_ID,
      )
      blockPlainConnectOnCount = 1
      succeedBlockedPlainConnectAfterCancellation = true
    }
    val runtime = runtime(executor, fakeSession, deterministicPassStore())
    val reconnect = AtomicReference<Thread>()
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 0x70 })
    try {
      runtime.openSession()
      reconnect.set(thread(name = "stored-target-connect-pass-race") {
        executor.runCapturedImmediateTask()
      })
      assertTrue(
        "stored reconnect did not enter native connect",
        fakeSession.blockedPlainConnectEntered.await(5, TimeUnit.SECONDS),
      )

      assertTrue(runtime.consumeEnrollmentUri("https://new.example/enroll#invite=$token"))
      reconnect.get().join(TimeUnit.SECONDS.toMillis(5))

      assertFalse("cancelled stored reconnect did not finish", reconnect.get().isAlive)
      assertEquals(1, fakeSession.plainConnectCount)
      assertEquals(NativeConnectionState.DISCONNECTED, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(0, fakeSession.directSyncBeginCount)

      executor.runCapturedImmediateTask()
      assertTrue(fakeSession.lifecycleEvents.contains("disconnect"))
      assertTrue(runtime.snapshot().pendingAccessPass != null)
    } finally {
      reconnect.get()?.join(TimeUnit.SECONDS.toMillis(5))
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun stagedPassDuringStoredBootstrapPreventsAReplacementPlainRetry() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://old.example:443",
        expectedUserId = USER_ID,
      )
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(
      executor,
      fakeSession,
      deterministicPassStore(),
      directTransport = transport,
    )
    val tokenBytes = ByteArray(32) { 0x71 }
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes)
    try {
      runtime.openSession()
      executor.runCapturedImmediateTask()
      assertEquals(NativeReconnectStage.BOOTSTRAPPING, runtime.reconnectPlanForTesting()?.stage)
      assertEquals(1, fakeSession.plainConnectCount)
      assertEquals(1, transport.pendingCount())
      val delayedSchedulesBeforeFailure = executor.delayedScheduleCount()

      assertTrue(runtime.consumeEnrollmentUri("https://new.example/enroll#invite=$token"))
      val pending = checkNotNull(runtime.snapshot().pendingAccessPass)
      // Pass staging is review intent: the authenticated bootstrap stays live,
      // but its stored-origin scope may no longer create another transport.
      assertEquals(NativeReconnectStage.BOOTSTRAPPING, runtime.reconnectPlanForTesting()?.stage)
      fakeSession.nextLiveBufferFailure.set(
        NativeMobileRetryableException(NativeMobileRetryableReason.TRANSPORT),
      )

      transport.completeNext(
        NativeDirectHttpResult.Success("stored-bootstrap-count".toByteArray()),
      )
      executor.runCapturedImmediateTask()

      assertEquals(1, fakeSession.plainConnectCount)
      assertEquals(0, fakeSession.accessPassConnectCount)
      assertEquals(delayedSchedulesBeforeFailure, executor.delayedScheduleCount())
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertEquals(pending.flowId, runtime.snapshot().pendingAccessPass?.flowId)

      runtime.connectPendingAccessPass(pending.flowId)
      assertEquals(1, fakeSession.plainConnectCount)
      assertEquals(1, fakeSession.accessPassConnectCount)
      assertArrayEquals(tokenBytes, fakeSession.lastAccessPass)
      assertEquals("https://new.example:443", runtime.snapshot().binding?.canonicalServerOrigin)
    } finally {
      tokenBytes.fill(0)
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun storedTargetTaskMayRunBeforeFutureAssignmentWithoutDuplicatingItsOwner() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true).apply {
      runNextImmediateTaskInline()
    }
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://resume.example:443",
        expectedUserId = USER_ID,
      )
    }
    val runtime = runtime(executor, fakeSession)
    try {
      val opened = runtime.openSession()

      assertEquals(NativeConnectionState.CONNECTED, opened.connectionState)
      assertEquals(1, executor.immediateScheduleCount())
      assertEquals(1, fakeSession.plainConnectCount)
      assertEquals(0, fakeSession.accessPassConnectCount)
      assertEquals(1, fakeSession.directSyncBeginCount)
      assertEquals(NativeReconnectStage.BOOTSTRAPPING, runtime.reconnectPlanForTesting()?.stage)
      assertEquals(NativeReconnectTrigger.STORED_TARGET, runtime.reconnectPlanForTesting()?.trigger)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundDuringStoredTargetLoadClosesCandidateAndNeverCreatesAReconnectOwner() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val loadEntered = CountDownLatch(1)
    val loadRelease = CountDownLatch(1)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://resume.example:443",
        expectedUserId = USER_ID,
      )
      storedReconnectTargetLoadEntered = loadEntered
      storedReconnectTargetLoadRelease = loadRelease
    }
    val runtime = runtime(executor, fakeSession)
    val openError = AtomicReference<VeilMobileRuntimeException?>()
    val opener = thread(name = "stored-target-open") {
      try {
        runtime.openSession()
      } catch (error: VeilMobileRuntimeException) {
        openError.set(error)
      }
    }
    try {
      assertTrue("stored target load did not begin", loadEntered.await(5, TimeUnit.SECONDS))
      runtime.lockForBackground()
      loadRelease.countDown()
      opener.join(TimeUnit.SECONDS.toMillis(5))

      assertFalse("stored target opener did not finish", opener.isAlive)
      assertEquals("E_VEIL_LOCKED", openError.get()?.code)
      assertTrue(fakeSession.closed)
      assertEquals(0, fakeSession.plainConnectCount)
      assertNull(runtime.reconnectPlanForTesting())
      assertNull(runtime.snapshot().binding)
    } finally {
      loadRelease.countDown()
      opener.join(TimeUnit.SECONDS.toMillis(5))
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun explicitConnectSupersedesWaitingStoredTargetAndLateTaskCannotTouchNewSocket() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://old.example:443",
        expectedUserId = USER_ID,
      )
    }
    val runtime = runtime(executor, fakeSession)
    try {
      runtime.openSession()
      val authenticated = runtime.connect("https://new.example")

      assertEquals("https://new.example:443", authenticated.canonicalServerOrigin)
      assertEquals(1, fakeSession.plainConnectCount)
      assertNull(runtime.reconnectPlanForTesting())
      val disconnectsBeforeLateTask = fakeSession.lifecycleEvents.count { it == "disconnect" }

      executor.runCapturedImmediateTask()

      assertEquals(1, fakeSession.plainConnectCount)
      assertEquals(
        disconnectsBeforeLateTask,
        fakeSession.lifecycleEvents.count { it == "disconnect" },
      )
      assertEquals("https://new.example:443", runtime.snapshot().binding?.canonicalServerOrigin)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun storedTargetFirstTypedFailureStartsBackoffAtOrdinalZero() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://resume.example:443",
        expectedUserId = USER_ID,
      )
      queuedConnectFailures.add(
        NativeMobileRetryableException(NativeMobileRetryableReason.TRANSPORT),
      )
    }
    val runtime = runtime(executor, fakeSession)
    try {
      runtime.openSession()
      executor.runCapturedImmediateTask()

      assertEquals(1, fakeSession.plainConnectCount)
      assertEquals(0, fakeSession.accessPassConnectCount)
      assertEquals(
        NativeReconnectPlanDebug(
          reason = NativeMobileRetryableReason.TRANSPORT,
          failureOrdinal = 0,
          delayMillis = 1_000L,
          stage = NativeReconnectStage.WAITING,
        ),
        runtime.reconnectPlanForTesting(),
      )
      assertEquals(1, executor.delayedScheduleCount())
      assertEquals(NativeConnectionState.CONNECTING, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun storedTargetRejectsAValidDifferentAuthenticatedAccountWithoutRetry() {
    val executor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val fakeSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://resume.example:443",
        expectedUserId = USER_ID,
      )
      authenticatedUserId = "550e8400-e29b-41d4-a716-446655440002"
    }
    val runtime = runtime(executor, fakeSession)
    try {
      runtime.openSession()
      executor.runCapturedImmediateTask()

      assertEquals(1, fakeSession.plainConnectCount)
      assertEquals(0, fakeSession.accessPassConnectCount)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(0, fakeSession.directSyncBeginCount)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun malformedOrUnreadableStoredTargetFailsOpenClosedBeforeNetworkUse() {
    val malformedExecutor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val malformedSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://RESUME.example:443",
        expectedUserId = USER_ID,
      )
    }
    val malformedRuntime = runtime(malformedExecutor, malformedSession)
    try {
      val error = assertThrows(VeilMobileRuntimeException::class.java) {
        malformedRuntime.openSession()
      }
      assertEquals("E_VEIL_OPEN", error.code)
      assertTrue(malformedSession.closed)
      assertEquals(0, malformedSession.plainConnectCount)
      assertEquals(0, malformedSession.accessPassConnectCount)
      assertEquals(NativeSessionState.ERROR, malformedRuntime.snapshot().sessionState)
      assertEquals(NativeConnectionState.DISCONNECTED, malformedRuntime.snapshot().connectionState)
      assertNull(malformedRuntime.snapshot().binding)
    } finally {
      malformedRuntime.lockSession()
      malformedExecutor.shutdownNow()
    }

    val unreadableExecutor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val unreadableSession = FakeSession().apply {
      storedReconnectTargetFailure = IllegalStateException("synthetic SQLCipher recovery failure")
    }
    val unreadableRuntime = runtime(unreadableExecutor, unreadableSession)
    try {
      val error = assertThrows(VeilMobileRuntimeException::class.java) {
        unreadableRuntime.openSession()
      }
      assertEquals("E_VEIL_OPEN", error.code)
      assertTrue(unreadableSession.closed)
      assertEquals(0, unreadableSession.plainConnectCount)
      assertEquals(0, unreadableSession.accessPassConnectCount)
      assertNull(unreadableRuntime.snapshot().binding)
    } finally {
      unreadableRuntime.lockSession()
      unreadableExecutor.shutdownNow()
    }
  }

  @Test
  fun backgroundOrSchedulerRejectionRevokesStoredTargetOwnerBeforeItCanConnect() {
    val backgroundExecutor = CapturingScheduledExecutor(captureImmediateTasks = true)
    val backgroundSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://resume.example:443",
        expectedUserId = USER_ID,
      )
    }
    val backgroundRuntime = runtime(backgroundExecutor, backgroundSession)
    try {
      backgroundRuntime.openSession()
      backgroundRuntime.lockForBackground()
      backgroundExecutor.runCapturedImmediateTask()
      assertEquals(0, backgroundSession.plainConnectCount)
      assertNull(backgroundRuntime.reconnectPlanForTesting())
      assertNull(backgroundRuntime.snapshot().binding)
    } finally {
      backgroundRuntime.lockSession()
      backgroundExecutor.shutdownNow()
    }

    val rejectedExecutor = CapturingScheduledExecutor(captureImmediateTasks = true).apply {
      rejectImmediateTasks = true
    }
    val rejectedSession = FakeSession().apply {
      storedReconnectTarget = NativeMobileReconnectTarget(
        canonicalServerOrigin = "https://resume.example:443",
        expectedUserId = USER_ID,
      )
    }
    val rejectedRuntime = runtime(rejectedExecutor, rejectedSession)
    try {
      val opened = rejectedRuntime.openSession()
      assertEquals(NativeConnectionState.ERROR, opened.connectionState)
      assertNull(opened.binding)
      assertNull(rejectedRuntime.reconnectPlanForTesting())
      assertEquals(0, rejectedSession.plainConnectCount)
      assertEquals(0, rejectedSession.accessPassConnectCount)
    } finally {
      rejectedRuntime.lockSession()
      rejectedExecutor.shutdownNow()
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
      val opened = runtime.openSession()
      assertNull(opened.directGeneration)
      val nextCapture = runtime.snapshot()
      assertEquals(opened.runtimeRevision + 1, nextCapture.runtimeRevision)
      val firstBinding = runtime.connect("https://access.example")
      val firstGenerationSnapshot = runtime.snapshot()
      val firstGeneration = checkNotNull(firstGenerationSnapshot.directGeneration)
      val sameGenerationSnapshot = runtime.snapshot()
      assertEquals(firstGeneration, sameGenerationSnapshot.directGeneration)
      assertEquals(
        firstGenerationSnapshot.runtimeRevision + 1,
        sameGenerationSnapshot.runtimeRevision,
      )
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
      val secondGeneration = checkNotNull(runtime.snapshot().directGeneration)
      assertTrue(secondGeneration > firstGeneration)
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
      assertTrue("quiescent authenticated live replay must open Direct", complete.directoryReady)
      assertEquals(1, fakeSession.liveReplayPumpCount)
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
  fun readyDirectContinuouslyReplaysBoundedEventsAndPublishesContentRevision() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      projectionChangeOnOrAfterReplayPump = 2
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(
      executor,
      fakeSession,
      directTransport = transport,
      directLivePollIntervalMillis = 10L,
    )
    val publishedContentRevisions = CopyOnWriteArrayList<Long>()
    runtime.addListener { snapshot ->
      snapshot.directContentRevision?.let(publishedContentRevisions::add)
    }
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(
        NativeDirectHttpResult.Success("directory-before-continuous-live".toByteArray()),
      )

      assertTrue(
        "continuous native replay did not publish its aggregate invalidation",
        awaitCondition { runtime.snapshot().directContentRevision == 1L },
      )
      val ready = runtime.snapshot()
      assertTrue(ready.directoryReady)
      assertEquals(NativeConnectionState.CONNECTED, ready.connectionState)
      assertEquals(1L, ready.directContentRevision)
      assertTrue(
        "content invalidation changed native state without a public listener event",
        publishedContentRevisions.contains(1L),
      )
      assertTrue(fakeSession.liveReplayPumpCount >= 2)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun terminalContinuousReplayRevokesTheExactReadyGeneration() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      failLiveReplayOnOrAfterPump = 2
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(
      executor,
      fakeSession,
      directTransport = transport,
      directLivePollIntervalMillis = 10L,
    )
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(
        NativeDirectHttpResult.Success("directory-before-continuous-terminal".toByteArray()),
      )

      assertTrue(
        "terminal continuous replay did not revoke the generation",
        awaitCondition { runtime.snapshot().connectionState == NativeConnectionState.ERROR },
      )
      awaitRuntimeIdle(runtime)
      val failed = runtime.snapshot()
      assertEquals(2, fakeSession.liveReplayPumpCount)
      assertEquals(NativeDirectDirectoryState.ERROR, failed.directDirectoryState)
      assertEquals(NativeDirectHistoryState.ERROR, failed.directHistoryState)
      assertEquals(NativeSecureSyncState.ERROR, failed.secureSyncState)
      assertNull(failed.directGeneration)
      assertNull(failed.directContentRevision)
      assertNull(failed.binding)
      assertFalse(failed.directoryReady)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun contradictoryContinuousReadyReplayWithPendingOutboxRevokesTheGeneration() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("46", "Continuous", "47", "continuous", false)
    try {
      completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      fakeSession.liveReplayProgresses.add(
        NativeDirectLiveReplayProgress(
          consumed = 0,
          projectionChanged = false,
          needsImmediatePump = false,
          outboxReplayRequired = true,
          ready = true,
        ),
      )

      executor.runCapturedDelayedTask()

      val failed = runtime.snapshot()
      assertEquals(2, fakeSession.liveReplayPumpCount)
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertEquals(NativeDirectDirectoryState.ERROR, failed.directDirectoryState)
      assertEquals(NativeDirectHistoryState.ERROR, failed.directHistoryState)
      assertEquals(NativeSecureSyncState.ERROR, failed.secureSyncState)
      assertNull(failed.directGeneration)
      assertNull(failed.directContentRevision)
      assertNull(failed.binding)
      assertFalse(failed.directoryReady)
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertNull(runtime.reconnectPlanForTesting())
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundRevocationMakesAnAlreadyScheduledContinuousReplayANoOp() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(
      executor,
      fakeSession,
      directTransport = transport,
      directLivePollIntervalMillis = 200L,
    )
    val delayedWindowElapsed = CountDownLatch(1)
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(
        NativeDirectHttpResult.Success("directory-before-scheduled-background".toByteArray()),
      )

      assertTrue(
        "initial Direct replay did not publish Ready",
        awaitCondition { runtime.snapshot().directoryReady },
      )
      val replayCountBeforeRevocation = fakeSession.liveReplayPumpCount
      assertEquals(1, replayCountBeforeRevocation)

      runtime.lockForBackground()
      executor.schedule(
        { delayedWindowElapsed.countDown() },
        350L,
        TimeUnit.MILLISECONDS,
      )
      assertTrue(
        "scheduled replay observation window did not elapse",
        delayedWindowElapsed.await(5, TimeUnit.SECONDS),
      )
      awaitRuntimeIdle(runtime)

      val locked = runtime.snapshot()
      assertEquals(replayCountBeforeRevocation, fakeSession.liveReplayPumpCount)
      assertEquals(NativeSessionState.LOCKED, locked.sessionState)
      assertEquals(NativeConnectionState.DISCONNECTED, locked.connectionState)
      assertNull(locked.directGeneration)
      assertNull(locked.directContentRevision)
      assertFalse(locked.directoryReady)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun directHistoryRunsOneExactRequestAtATimeAndRequiresBoundedLiveReplayBeforeReady() {
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
    fakeSession.liveReplayProgresses.add(
      NativeDirectLiveReplayProgress(
        consumed = 64,
        projectionChanged = true,
        needsImmediatePump = true,
        outboxReplayRequired = false,
        ready = false,
      ),
    )
    fakeSession.liveReplayProgresses.add(
      NativeDirectLiveReplayProgress(
        consumed = 0,
        projectionChanged = false,
        needsImmediatePump = false,
        outboxReplayRequired = true,
        ready = false,
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
      awaitRuntimeIdle(runtime)
      val terminal = runtime.snapshot()
      assertTrue(secondHistoryBody.all { it == 0.toByte() })
      assertEquals(NativeDirectHistoryState.SYNCHRONIZED, terminal.directHistoryState)
      assertEquals(NativeSecureSyncState.HISTORY_SYNCHRONIZED, terminal.secureSyncState)
      assertEquals(NativeConnectionState.CONNECTED, terminal.connectionState)
      assertTrue("Direct must open only after the second quiescent replay turn", terminal.directoryReady)
      assertEquals(2, fakeSession.liveReplayPumpCount)
      assertEquals(2, fakeSession.historyInstalledResponseCopies.size)
      assertTrue(fakeSession.liveBufferPumpCount >= 5)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun quiescentLiveReplayKeepsDirectClosedUntilEveryBoundedOutboxTurnCompletes() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val secondOutboxTurnEntered = CountDownLatch(1)
    val releaseSecondOutboxTurn = CountDownLatch(1)
    fakeSession.outboxReplayProgresses.add(
      NativeDirectOutboxReplayProgress(
        visited = 64,
        enqueued = 63,
        needsImmediatePump = true,
        replayComplete = false,
      ),
    )
    fakeSession.outboxReplayProgresses.add(
      NativeDirectOutboxReplayProgress(
        visited = 3,
        enqueued = 2,
        needsImmediatePump = false,
        replayComplete = true,
      ),
    )
    fakeSession.blockOutboxReplayOnPump = 2
    fakeSession.outboxReplayEntered = secondOutboxTurnEntered
    fakeSession.outboxReplayRelease = releaseSecondOutboxTurn
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)

      transport.completeNext(
        NativeDirectHttpResult.Success("directory-before-outbox-barrier".toByteArray()),
      )
      assertTrue(
        "second bounded outbox turn did not start",
        secondOutboxTurnEntered.await(5, TimeUnit.SECONDS),
      )

      val draining = runtime.snapshot()
      assertEquals(NativeConnectionState.CONNECTED, draining.connectionState)
      assertEquals(NativeDirectHistoryState.SYNCHRONIZED, draining.directHistoryState)
      assertEquals(1, fakeSession.liveReplayPumpCount)
      assertEquals(2, fakeSession.outboxReplayPumpCount)
      assertFalse("an incomplete native outbox cursor must keep Direct closed", draining.directoryReady)

      releaseSecondOutboxTurn.countDown()
      awaitRuntimeIdle(runtime)

      val ready = runtime.snapshot()
      assertTrue("only Rust's terminal outbox receipt may publish Ready", ready.directoryReady)
      assertEquals(NativeSecureSyncState.HISTORY_SYNCHRONIZED, ready.secureSyncState)
      assertEquals(2, fakeSession.outboxReplayPumpCount)
      assertTrue(fakeSession.outboxReplayComplete)
    } finally {
      releaseSecondOutboxTurn.countDown()
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun terminalOutboxReplayFailureRevokesTheGenerationWithoutPublishingReady() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply { failOutboxReplayPump = true }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)

      transport.completeNext(
        NativeDirectHttpResult.Success("directory-before-outbox-failure".toByteArray()),
      )
      awaitRuntimeIdle(runtime)

      val failed = runtime.snapshot()
      assertEquals(1, fakeSession.liveReplayPumpCount)
      assertEquals(1, fakeSession.outboxReplayPumpCount)
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertEquals(NativeDirectDirectoryState.ERROR, failed.directDirectoryState)
      assertEquals(NativeDirectHistoryState.ERROR, failed.directHistoryState)
      assertEquals(NativeSecureSyncState.ERROR, failed.secureSyncState)
      assertNull(failed.directGeneration)
      assertNull(failed.directContentRevision)
      assertNull(failed.binding)
      assertFalse(failed.directoryReady)
      assertEquals(1, fakeSession.directLeaseCancellations)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun contradictoryReadyLiveReplayWithPendingOutboxFailsClosed() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    fakeSession.liveReplayProgresses.add(
      NativeDirectLiveReplayProgress(
        consumed = 0,
        projectionChanged = false,
        needsImmediatePump = false,
        outboxReplayRequired = true,
        ready = true,
      ),
    )
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)

      transport.completeNext(
        NativeDirectHttpResult.Success("directory-before-contradictory-ready".toByteArray()),
      )
      awaitRuntimeIdle(runtime)

      val failed = runtime.snapshot()
      assertEquals(1, fakeSession.liveReplayPumpCount)
      assertEquals(0, fakeSession.outboxReplayPumpCount)
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertEquals(NativeDirectDirectoryState.ERROR, failed.directDirectoryState)
      assertEquals(NativeDirectHistoryState.ERROR, failed.directHistoryState)
      assertEquals(NativeSecureSyncState.ERROR, failed.secureSyncState)
      assertNull(failed.directGeneration)
      assertNull(failed.directContentRevision)
      assertNull(failed.binding)
      assertFalse(failed.directoryReady)
      assertEquals(1, fakeSession.directLeaseCancellations)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun terminalDirectLiveReplayFailsClosedWithoutPublishingReady() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    fakeSession.failLiveReplayPump = true
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)

      transport.completeNext(NativeDirectHttpResult.Success("directory-before-live-stop".toByteArray()))
      awaitRuntimeIdle(runtime)

      val failed = runtime.snapshot()
      assertEquals(1, fakeSession.liveReplayPumpCount)
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertEquals(NativeDirectDirectoryState.ERROR, failed.directDirectoryState)
      assertEquals(NativeDirectHistoryState.ERROR, failed.directHistoryState)
      assertEquals(NativeSecureSyncState.ERROR, failed.secureSyncState)
      assertNull(failed.binding)
      assertFalse(failed.directoryReady)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundRevocationWinsAgainstAnInFlightReadyReplay() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val replayEntered = CountDownLatch(1)
    val releaseReplay = CountDownLatch(1)
    fakeSession.directReplayEntered = replayEntered
    fakeSession.directReplayRelease = releaseReplay
    try {
      runtime.openSession()
      runtime.connect("https://access.example")
      completeOwnPreKeyBootstrap(runtime, transport)

      transport.completeNext(NativeDirectHttpResult.Success("directory-before-background".toByteArray()))
      assertTrue("native live replay did not start", replayEntered.await(5, TimeUnit.SECONDS))
      assertFalse(runtime.snapshot().directoryReady)

      runtime.lockForBackground()
      assertFalse(runtime.snapshot().directoryReady)
      assertEquals(NativeConnectionState.DISCONNECTED, runtime.snapshot().connectionState)

      releaseReplay.countDown()
      awaitRuntimeIdle(runtime)
      val locked = runtime.snapshot()
      assertEquals(NativeSessionState.LOCKED, locked.sessionState)
      assertFalse(locked.directoryReady)
      assertNull(locked.binding)
      assertTrue(fakeSession.directLeaseCancellations >= 1)
    } finally {
      releaseReplay.countDown()
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
  fun invalidDirectTextPlaintextRejectsSynchronouslyWithoutCrossingNativeOrChangingReadyState() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = false)
    val invalidPlaintexts = listOf(
      "",
      "\u00e9".repeat((32 * 1024 / 2) + 1),
      String(charArrayOf(0xD800.toChar())),
    )
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val readyBefore = runtime.snapshot()
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size

      invalidPlaintexts.forEach { plaintext ->
        val result = DirectTextSendCapture()
        runtime.sendDirectText(conversation.conversationId, generation, plaintext, result)

        assertEquals(
          "invalid plaintext must complete before sendDirectText returns",
          1,
          result.completionCount.get(),
        )
        assertEquals(NativeDirectTextSendResult.REJECTED, result.await())
      }

      assertEquals(0, fakeSession.directTextSendCount)
      assertTrue(fakeSession.directTextPlaintextReferences.isEmpty())
      assertTrue(fakeSession.directTextPlaintextCopies.isEmpty())
      assertEquals(0, fakeSession.peerPreKeyRequestCount)
      assertEquals(requestCount, transport.requests.size)
      assertEquals(signatureCount, fakeSession.signedRequestCopies.size)
      val readyAfter = runtime.snapshot()
      assertEquals(readyBefore.directGeneration, readyAfter.directGeneration)
      assertEquals(readyBefore.directContentRevision, readyAfter.directContentRevision)
      assertEquals(readyBefore.connectionState, readyAfter.connectionState)
      assertEquals(readyBefore.directConversations, readyAfter.directConversations)
      assertEquals(generation, readyAfter.directGeneration)
      assertTrue(readyAfter.directoryReady)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun readyDirectTextSendEnqueuesExactlyOnceAndPublishesOnlyAProjectionInvalidation() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = false)
    val plaintext = "one atomic native Direct message"
    val expectedUtf8 = plaintext.toByteArray()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val revisionBefore = checkNotNull(runtime.snapshot().directContentRevision)
      val result = DirectTextSendCapture()

      runtime.sendDirectText(conversation.conversationId, generation, plaintext, result)

      assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(1, fakeSession.directTextSendCount)
      assertEquals(requestCount, transport.requests.size)
      assertEquals(signatureCount, fakeSession.signedRequestCopies.size)
      assertEquals(0, fakeSession.peerPreKeyRequestCount)
      assertArrayEquals(expectedUtf8, fakeSession.directTextPlaintextCopies.single())
      assertTrue(
        "the Kotlin-owned plaintext must be wiped as soon as native accepts it",
        fakeSession.directTextPlaintextReferences.single().all { it == 0.toByte() },
      )

      val accepted = runtime.snapshot()
      assertEquals(revisionBefore + 1, accepted.directContentRevision)
      assertTrue(accepted.directoryReady)
      assertEquals(NativeConnectionState.CONNECTED, accepted.connectionState)
      assertEquals(
        "send acceptance must invalidate native projection, not fabricate a Kotlin row",
        0,
        fakeSession.directProjectionCount,
      )
      publishDirectMessagesForTest(runtime, conversation.conversationId)
      assertEquals(1, fakeSession.directProjectionCount)
    } finally {
      expectedUtf8.fill(0)
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun needsPreKeyDirectTextSendPerformsOneDestructiveGetAndOneSamePlaintextRetry() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.NEEDS_PRE_KEY)
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val plaintext = "retry this exact plaintext only after peer prekey install"
    val expectedUtf8 = plaintext.toByteArray()
    val response = "authenticated-peer-prekey-for-send".toByteArray()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val result = DirectTextSendCapture()

      runtime.sendDirectText(conversation.conversationId, generation, plaintext, result)

      assertEquals(0, result.completionCount.get())
      assertEquals(1, fakeSession.directTextSendCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(signatureCount + 1, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount + 1, transport.requests.size)
      assertEquals(1, transport.pendingCount())
      assertEquals(NativeDirectHttpMethod.GET, transport.requests.last().method)
      assertEquals("/v1/prekeys/${"cd".repeat(32)}", transport.requests.last().requestTarget)
      assertEquals(NativeDirectHttpLimits.PREKEY_BYTES, transport.requests.last().responseLimitBytes)
      assertTrue(transport.requests.last().body.isEmpty())
      assertArrayEquals(expectedUtf8, fakeSession.directTextPlaintextReferences.single())

      transport.completeNext(NativeDirectHttpResult.Success(response))
      awaitRuntimeIdle(runtime)

      assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(2, fakeSession.directTextSendCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(1, fakeSession.peerPreKeyInstallCount)
      assertEquals(signatureCount + 1, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount + 1, transport.requests.size)
      assertEquals(2, fakeSession.directTextPlaintextCopies.size)
      fakeSession.directTextPlaintextCopies.forEach { copy ->
        assertArrayEquals(expectedUtf8, copy)
      }
      assertTrue(
        "both native attempts must borrow one retained plaintext owner",
        fakeSession.directTextPlaintextReferences[0] ===
          fakeSession.directTextPlaintextReferences[1],
      )
      assertTrue(
        "the retained plaintext must be wiped after the terminal retry",
        fakeSession.directTextPlaintextReferences.all { reference ->
          reference.all { it == 0.toByte() }
        },
      )
      assertTrue(response.all { it == 0.toByte() })
      assertTrue(runtime.snapshot().directoryReady)
      assertEquals(1L, runtime.snapshot().directContentRevision)
    } finally {
      expectedUtf8.fill(0)
      response.fill(0)
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun secondNeedsPreKeyOutcomeNeverStartsAnotherGetAndFailsClosed() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.NEEDS_PRE_KEY)
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.NEEDS_PRE_KEY)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val expectedUtf8 = "never perform a second destructive prekey GET".toByteArray()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val result = DirectTextSendCapture()

      runtime.sendDirectText(
        conversation.conversationId,
        generation,
        expectedUtf8.toString(Charsets.UTF_8),
        result,
      )
      transport.completeNext(
        NativeDirectHttpResult.Success("peer-prekey-still-did-not-open-ratchet".toByteArray()),
      )
      awaitRuntimeIdle(runtime)

      assertEquals(NativeDirectTextSendResult.UNAVAILABLE, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(2, fakeSession.directTextSendCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(1, fakeSession.peerPreKeyInstallCount)
      assertEquals(signatureCount + 1, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount + 1, transport.requests.size)
      assertEquals(0, transport.pendingCount())
      assertTrue(
        fakeSession.directTextPlaintextReferences.all { reference ->
          reference.all { it == 0.toByte() }
        },
      )
      val failed = runtime.snapshot()
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertNull(failed.directGeneration)
      assertNull(failed.directContentRevision)
      assertNull(failed.binding)
      assertFalse(failed.directoryReady)
      assertEquals(1, fakeSession.directLeaseCancellations)
    } finally {
      expectedUtf8.fill(0)
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun acceptedForReplayCompletesOnceButRevokesTheLostTransportGeneration() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_FOR_REPLAY)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = false)
    val publishedAfterSend = CopyOnWriteArrayList<VeilMobileRuntimeSnapshot>()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val delayedSchedulesBeforeSend = executor.delayedScheduleCount()
      val result = DirectTextSendCapture()
      runtime.addListener(publishedAfterSend::add)

      runtime.sendDirectText(
        conversation.conversationId,
        generation,
        "durable locally even though transport authority was lost",
        result,
      )

      assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(1, fakeSession.directTextSendCount)
      assertEquals(requestCount, transport.requests.size)
      assertEquals(delayedSchedulesBeforeSend + 1, executor.delayedScheduleCount())
      assertTrue(fakeSession.directTextPlaintextReferences.single().all { it == 0.toByte() })
      val revoked = runtime.snapshot()
      assertEquals(NativeConnectionState.CONNECTING, revoked.connectionState)
      assertNull(revoked.directGeneration)
      assertNull(revoked.directContentRevision)
      assertNull(revoked.binding)
      assertFalse(revoked.directoryReady)
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertEquals(
        NativeReconnectPlanDebug(
          reason = NativeMobileRetryableReason.TRANSPORT,
          failureOrdinal = 0,
          delayMillis = 1_000L,
          stage = NativeReconnectStage.WAITING,
        ),
        runtime.reconnectPlanForTesting(),
      )
      assertTrue(
        "React listeners must observe the native generation revoke",
        publishedAfterSend.any { published ->
          published.connectionState == NativeConnectionState.CONNECTING &&
            published.directGeneration == null &&
            published.directContentRevision == null &&
            published.binding == null &&
            !published.directoryReady
        },
      )
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun acceptedSessionInvalidCompletesOnceAndRevokesWithoutRetryPermission() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_SESSION_INVALID)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = false)
    val publishedAfterSend = CopyOnWriteArrayList<VeilMobileRuntimeSnapshot>()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val result = DirectTextSendCapture()
      runtime.addListener(publishedAfterSend::add)

      runtime.sendDirectText(
        conversation.conversationId,
        generation,
        "durable locally but the authenticated session is invalid",
        result,
      )

      assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(1, fakeSession.directTextSendCount)
      assertEquals(requestCount, transport.requests.size)
      assertTrue(fakeSession.directTextPlaintextReferences.single().all { it == 0.toByte() })
      val revoked = runtime.snapshot()
      assertEquals(NativeConnectionState.ERROR, revoked.connectionState)
      assertNull(revoked.directGeneration)
      assertNull(revoked.directContentRevision)
      assertNull(revoked.binding)
      assertFalse(revoked.directoryReady)
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertNull(runtime.reconnectPlanForTesting())
      assertTrue(
        "React listeners must observe the non-retryable session revoke",
        publishedAfterSend.any { published ->
          published.connectionState == NativeConnectionState.ERROR &&
            published.directGeneration == null &&
            published.directContentRevision == null &&
            published.binding == null &&
            !published.directoryReady
        },
      )
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun mobileRetryableReasonMappingIsClosedOverTheExactNativeAllowlist() {
    assertEquals(
      NativeMobileRetryableReason.TRANSPORT,
      MobileRetryableReason.TRANSPORT.toNativeMobileRetryableReason(),
    )
    assertEquals(
      NativeMobileRetryableReason.ACK_DEADLINE,
      MobileRetryableReason.ACK_DEADLINE.toNativeMobileRetryableReason(),
    )
    val translated = assertThrows(NativeMobileRetryableException::class.java) {
      translateMobileRetryable<Unit> {
        throw VeilException.MobileRetryable(MobileRetryableReason.ACK_DEADLINE)
      }
    }
    assertEquals(NativeMobileRetryableReason.ACK_DEADLINE, translated.reason)

    val terminal = VeilException.Session("transport ACK_DEADLINE retryable")
    val preserved = assertThrows(VeilException.Session::class.java) {
      translateMobileRetryable<Unit> { throw terminal }
    }
    assertTrue(preserved === terminal)
  }

  @Test
  fun typedTransportAndAckDeadlineReplayFailuresRemainDistinctReconnectReasons() {
    val cases = listOf(
      NativeMobileRetryableReason.TRANSPORT,
      NativeMobileRetryableReason.ACK_DEADLINE,
    )
    cases.forEachIndexed { index, reason ->
      val executor = CapturingScheduledExecutor()
      val fakeSession = FakeSession()
      val transport = ControllableDirectTransport()
      val runtime = runtime(executor, fakeSession, directTransport = transport)
      val conversation = directConversation("2$index", "Typed $index", "3$index", "typed$index", false)
      try {
        completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
        fakeSession.nextLiveReplayFailure.set(NativeMobileRetryableException(reason))

        executor.runCapturedDelayedTask()

        assertEquals(
          NativeReconnectPlanDebug(
            reason = reason,
            failureOrdinal = 0,
            delayMillis = 1_000L,
            stage = NativeReconnectStage.WAITING,
          ),
          runtime.reconnectPlanForTesting(),
        )
        val reconnecting = runtime.snapshot()
        assertEquals(NativeConnectionState.CONNECTING, reconnecting.connectionState)
        assertNull(reconnecting.binding)
        assertNull(reconnecting.directGeneration)
      } finally {
        runtime.lockSession()
        executor.shutdownNow()
      }
    }
  }

  @Test
  fun sessionFailureWithRetryWordsRemainsTerminalAndNeverCreatesAPlan() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("24", "Terminal", "25", "terminal", false)
    try {
      completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      fakeSession.nextLiveReplayFailure.set(
        VeilException.Session("transport retry ACK_DEADLINE mobile retryable"),
      )

      executor.runCapturedDelayedTask()

      val failed = runtime.snapshot()
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertNull(failed.binding)
      assertNull(failed.directGeneration)
      assertNull(runtime.reconnectPlanForTesting())
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun reconnectConnectRetriesOnlyTheTypedAllowlistAndKeepsTheExactReason() {
    data class ReconnectConnectCase(
      val conversationSuffix: String,
      val peerSuffix: String,
      val failure: Throwable,
      val expectedReason: NativeMobileRetryableReason?,
    )

    val cases = listOf(
      ReconnectConnectCase(
        conversationSuffix = "40",
        peerSuffix = "41",
        failure = NativeMobileRetryableException(NativeMobileRetryableReason.ACK_DEADLINE),
        expectedReason = NativeMobileRetryableReason.ACK_DEADLINE,
      ),
      ReconnectConnectCase(
        conversationSuffix = "42",
        peerSuffix = "43",
        failure = VeilException.Session("transport retry ACK_DEADLINE mobile retryable"),
        expectedReason = null,
      ),
    )

    cases.forEachIndexed { index, case ->
      val executor = CapturingScheduledExecutor()
      val fakeSession = FakeSession()
      val transport = ControllableDirectTransport()
      val runtime = runtime(executor, fakeSession, directTransport = transport)
      val conversation = directConversation(
        case.conversationSuffix,
        "Reconnect connect $index",
        case.peerSuffix,
        "reconnect-connect-$index",
        false,
      )
      try {
        establishWaitingReconnect(runtime, fakeSession, transport, conversation)
        val schedulesBeforeConnect = executor.delayedScheduleCount()
        fakeSession.queuedConnectFailures.add(case.failure)

        executor.runCapturedDelayedTask()

        if (case.expectedReason != null) {
          assertEquals(
            NativeReconnectPlanDebug(
              reason = case.expectedReason,
              failureOrdinal = 1,
              delayMillis = 2_000L,
              stage = NativeReconnectStage.WAITING,
            ),
            runtime.reconnectPlanForTesting(),
          )
          assertEquals(schedulesBeforeConnect + 1, executor.delayedScheduleCount())
          assertEquals(NativeConnectionState.CONNECTING, runtime.snapshot().connectionState)
        } else {
          assertNull(runtime.reconnectPlanForTesting())
          assertEquals(schedulesBeforeConnect, executor.delayedScheduleCount())
          assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
        }
        assertEquals(2, fakeSession.plainConnectCount)
        assertNull(runtime.snapshot().binding)
        assertNull(runtime.snapshot().directGeneration)
      } finally {
        runtime.lockSession()
        executor.shutdownNow()
      }
    }
  }

  @Test
  fun reconnectTaskMayRunBeforeFutureAssignmentWithoutDuplicatingItsOwner() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_FOR_REPLAY)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("44", "Inline", "45", "inline", false)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val schedulesBeforeSend = executor.delayedScheduleCount()
      executor.runNextDelayedTaskInline()
      val result = DirectTextSendCapture()

      runtime.sendDirectText(conversation.conversationId, generation, "inline-reconnect", result)

      assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())
      assertEquals(schedulesBeforeSend + 1, executor.delayedScheduleCount())
      assertEquals(2, fakeSession.plainConnectCount)
      assertEquals(2, fakeSession.directSyncBeginCount)
      assertEquals(NativeReconnectStage.BOOTSTRAPPING, runtime.reconnectPlanForTesting()?.stage)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
      assertEquals(1, transport.pendingCount())

      val requestsAfterInlineRun = transport.requests.size
      executor.runCapturedDelayedTask()
      assertEquals(2, fakeSession.plainConnectCount)
      assertEquals(2, fakeSession.directSyncBeginCount)
      assertEquals(requestsAfterInlineRun, transport.requests.size)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun reconnectAfterAccessPassAuthenticationUsesOnlyThePlainBoundAccountPath() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_FOR_REPLAY)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, deterministicPassStore(), directTransport = transport)
    val conversation = directConversation("26", "Pass", "27", "pass", false)
    val tokenBytes = ByteArray(32) { 0x5c.toByte() }
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes)
    try {
      fakeSession.directoryInstalls.clear()
      fakeSession.directoryInstalls.add(
        NativeDirectDirectoryInstall(listOf(conversation), directoryComplete = true),
      )
      runtime.openSession()
      assertTrue(runtime.consumeEnrollmentUri("https://access.example/enroll#invite=$token"))
      val pending = checkNotNull(runtime.snapshot().pendingAccessPass)
      runtime.connectPendingAccessPass(pending.flowId)
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(NativeDirectHttpResult.Success("access-pass-directory".toByteArray()))
      awaitRuntimeIdle(runtime)
      val generation = checkNotNull(runtime.snapshot().directGeneration)
      assertEquals(1, fakeSession.accessPassConnectCount)
      assertEquals(0, fakeSession.plainConnectCount)
      assertNull(runtime.snapshot().pendingAccessPass)

      val result = DirectTextSendCapture()
      runtime.sendDirectText(conversation.conversationId, generation, "durable-pass-send", result)
      assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())
      executor.runCapturedDelayedTask()

      assertEquals(1, fakeSession.accessPassConnectCount)
      assertEquals(1, fakeSession.plainConnectCount)
      assertArrayEquals(tokenBytes, fakeSession.lastAccessPass)
      assertEquals(NativeReconnectStage.BOOTSTRAPPING, runtime.reconnectPlanForTesting()?.stage)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
    } finally {
      tokenBytes.fill(0)
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun reconnectRejectsAValidButDifferentAuthenticatedAccount() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_FOR_REPLAY)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("28", "Scope", "29", "scope", false)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      fakeSession.authenticatedUserId = "550e8400-e29b-41d4-a716-446655440099"

      val result = DirectTextSendCapture()
      runtime.sendDirectText(conversation.conversationId, generation, "wrong-account", result)
      assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())
      executor.runCapturedDelayedTask()

      val failed = runtime.snapshot()
      assertEquals(2, fakeSession.plainConnectCount)
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertNull(failed.binding)
      assertNull(failed.directGeneration)
      assertNull(runtime.reconnectPlanForTesting())
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun reconnectBackoffSurvivesAuthenticationAndResetsOnlyAtTheReadyOutboxBarrier() {
    val executor = CapturingScheduledExecutor()
    val sampledCaps = CopyOnWriteArrayList<Long>()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_FOR_REPLAY)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(
      executor,
      fakeSession,
      directTransport = transport,
      reconnectJitterMillis = { capMillis ->
        sampledCaps.add(capMillis)
        capMillis
      },
    )
    val conversation = directConversation("2a", "Backoff", "2b", "backoff", false)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val first = DirectTextSendCapture()
      runtime.sendDirectText(conversation.conversationId, generation, "first-retry", first)
      assertEquals(NativeDirectTextSendResult.ACCEPTED, first.await())
      assertEquals(listOf(1_000L), sampledCaps.toList())

      fakeSession.directoryInstalls.add(
        NativeDirectDirectoryInstall(listOf(conversation), directoryComplete = true),
      )
      fakeSession.nextOutboxReplayFailure.set(
        NativeMobileRetryableException(NativeMobileRetryableReason.ACK_DEADLINE),
      )
      executor.runCapturedDelayedTask()
      assertEquals(NativeReconnectStage.BOOTSTRAPPING, runtime.reconnectPlanForTesting()?.stage)
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(NativeDirectHttpResult.Success("first-reconnect-directory".toByteArray()))
      awaitRuntimeIdle(runtime)

      assertEquals(listOf(1_000L, 2_000L), sampledCaps.toList())
      assertEquals(
        NativeReconnectPlanDebug(
          reason = NativeMobileRetryableReason.ACK_DEADLINE,
          failureOrdinal = 1,
          delayMillis = 2_000L,
          stage = NativeReconnectStage.WAITING,
        ),
        runtime.reconnectPlanForTesting(),
      )

      fakeSession.directoryInstalls.add(
        NativeDirectDirectoryInstall(listOf(conversation), directoryComplete = true),
      )
      executor.runCapturedDelayedTask()
      completeOwnPreKeyBootstrap(runtime, transport)
      transport.completeNext(NativeDirectHttpResult.Success("second-reconnect-directory".toByteArray()))
      awaitRuntimeIdle(runtime)

      val ready = runtime.snapshot()
      assertTrue(ready.directoryReady)
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(3, fakeSession.plainConnectCount)

      fakeSession.directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_FOR_REPLAY)
      val afterReady = DirectTextSendCapture()
      runtime.sendDirectText(
        conversation.conversationId,
        checkNotNull(ready.directGeneration),
        "retry-after-ready",
        afterReady,
      )
      assertEquals(NativeDirectTextSendResult.ACCEPTED, afterReady.await())
      assertEquals(listOf(1_000L, 2_000L, 1_000L), sampledCaps.toList())
      assertEquals(0, runtime.reconnectPlanForTesting()?.failureOrdinal)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun reconnectFullJitterCapsExponentiallyAndSaturatesAtSixtySeconds() {
    val executor = CapturingScheduledExecutor()
    val sampledCaps = CopyOnWriteArrayList<Long>()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_FOR_REPLAY)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(
      executor,
      fakeSession,
      directTransport = transport,
      reconnectJitterMillis = { capMillis ->
        sampledCaps.add(capMillis)
        capMillis
      },
    )
    val conversation = directConversation("2c", "Jitter", "2d", "jitter", false)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      repeat(7) {
        fakeSession.queuedConnectFailures.add(
          NativeMobileRetryableException(NativeMobileRetryableReason.TRANSPORT),
        )
      }
      val result = DirectTextSendCapture()
      runtime.sendDirectText(conversation.conversationId, generation, "bounded-jitter", result)
      assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())

      repeat(7) { executor.runCapturedDelayedTask() }

      assertEquals(
        listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 32_000L, 60_000L, 60_000L),
        sampledCaps.toList(),
      )
      assertEquals(7, runtime.reconnectPlanForTesting()?.failureOrdinal)
      assertEquals(NativeReconnectStage.WAITING, runtime.reconnectPlanForTesting()?.stage)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundCancelsWaitingReconnectAndItsCapturedLateTaskCannotConnect() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("2e", "Background", "2f", "background", false)
    try {
      establishWaitingReconnect(runtime, fakeSession, transport, conversation)
      val connectCount = fakeSession.plainConnectCount

      runtime.lockForBackground()
      executor.runCapturedDelayedTask()
      awaitRuntimeIdle(runtime)

      assertEquals(connectCount, fakeSession.plainConnectCount)
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
    } finally {
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundCancelsConnectingReconnectEvenWhenNativeReturnsSuccessAfterCancellation() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("3a", "Connecting", "3b", "connecting", false)
    var reconnectTask: Thread? = null
    try {
      establishWaitingReconnect(runtime, fakeSession, transport, conversation)
      fakeSession.blockPlainConnectOnCount = 2
      fakeSession.succeedBlockedPlainConnectAfterCancellation = true
      reconnectTask = thread(start = true, name = "cancelled-connecting-reconnect") {
        executor.runCapturedDelayedTask()
      }
      assertTrue(
        "reconnect did not enter its native connect call",
        fakeSession.blockedPlainConnectEntered.await(5, TimeUnit.SECONDS),
      )

      runtime.lockForBackground()
      reconnectTask.join(5_000L)
      assertFalse("cancelled reconnect task did not finish", reconnectTask.isAlive)
      awaitRuntimeIdle(runtime)

      val locked = runtime.snapshot()
      assertEquals(2, fakeSession.plainConnectCount)
      assertFalse(fakeSession.closedDuringConnect.get())
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(NativeSessionState.LOCKED, locked.sessionState)
      assertEquals(NativeConnectionState.DISCONNECTED, locked.connectionState)
      assertNull(locked.binding)
    } finally {
      reconnectTask?.join(5_000L)
      executor.shutdownNow()
    }
  }

  @Test
  fun explicitLockCancelsWaitingReconnectAndItsCapturedLateTaskCannotConnect() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("30", "Lock", "31", "lock", false)
    try {
      establishWaitingReconnect(runtime, fakeSession, transport, conversation)
      val connectCount = fakeSession.plainConnectCount

      val locked = runtime.lockSession()
      executor.runCapturedDelayedTask()

      assertEquals(connectCount, fakeSession.plainConnectCount)
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(NativeSessionState.LOCKED, locked.sessionState)
    } finally {
      executor.shutdownNow()
    }
  }

  @Test
  fun manualDisconnectCancelsWaitingReconnectAndItsCapturedLateTaskCannotConnect() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("32", "Disconnect", "33", "disconnect", false)
    try {
      establishWaitingReconnect(runtime, fakeSession, transport, conversation)
      val connectCount = fakeSession.plainConnectCount

      val disconnected = runtime.disconnect()
      executor.runCapturedDelayedTask()

      assertEquals(connectCount, fakeSession.plainConnectCount)
      assertNull(runtime.reconnectPlanForTesting())
      assertEquals(NativeConnectionState.DISCONNECTED, disconnected.connectionState)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun manualConnectSupersedesOneWaitingReconnectAndTheOldLateTaskCannotDisconnectIt() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("34", "Manual", "35", "manual", false)
    try {
      establishWaitingReconnect(runtime, fakeSession, transport, conversation)

      val authenticated = runtime.connect("https://access.example")
      assertEquals(USER_ID, authenticated.userId)
      assertEquals(2, fakeSession.plainConnectCount)
      assertNull(runtime.reconnectPlanForTesting())
      executor.runCapturedDelayedTask()

      assertEquals(2, fakeSession.plainConnectCount)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
      assertEquals(USER_ID, runtime.snapshot().binding?.userId)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun sameAccountManualConnectSupersedesAnAuthenticatedReconnectBeforeLeaseBegin() {
    val executor = CapturingScheduledExecutor()
    val bootstrapTurn = AtomicInteger(0)
    val staleReconnectAccepted = CountDownLatch(1)
    val releaseStaleReconnect = CountDownLatch(1)
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(
      executor,
      fakeSession,
      directTransport = transport,
      directBootstrapOwnerBoundary = {
        if (bootstrapTurn.incrementAndGet() == 2) {
          staleReconnectAccepted.countDown()
          check(releaseStaleReconnect.await(5, TimeUnit.SECONDS)) {
            "stale authenticated reconnect was not released"
          }
        }
      },
    )
    val conversation = directConversation("38", "Owner", "39", "owner", false)
    var staleTask: Thread? = null
    try {
      establishWaitingReconnect(runtime, fakeSession, transport, conversation)
      staleTask = thread(start = true, name = "stale-authenticated-reconnect") {
        executor.runCapturedDelayedTask()
      }
      assertTrue(
        "reconnect did not reach its authenticated bootstrap boundary",
        staleReconnectAccepted.await(5, TimeUnit.SECONDS),
      )

      val replacement = runtime.connect("https://access.example")
      assertEquals(USER_ID, replacement.userId)
      assertEquals(2, fakeSession.directSyncBeginCount)
      assertEquals(3, fakeSession.plainConnectCount)
      assertNull(runtime.reconnectPlanForTesting())

      releaseStaleReconnect.countDown()
      staleTask.join(5_000L)
      assertFalse("stale reconnect task did not finish", staleTask.isAlive)
      assertEquals(2, fakeSession.directSyncBeginCount)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
      assertEquals(USER_ID, runtime.snapshot().binding?.userId)
      assertTrue(runtime.snapshot().directGeneration != null)
    } finally {
      releaseStaleReconnect.countDown()
      staleTask?.join(5_000L)
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun typedFailureInTheFirstBootstrapReturnsAuthenticatedWhileReconnectOwnsRecovery() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession().apply {
      nextLiveBufferFailure.set(
        NativeMobileRetryableException(NativeMobileRetryableReason.ACK_DEADLINE),
      )
    }
    val runtime = runtime(executor, fakeSession)
    try {
      runtime.openSession()

      val authenticated = runtime.connect("https://access.example")

      assertEquals(USER_ID, authenticated.userId)
      assertEquals(NativeConnectionState.CONNECTING, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertEquals(
        NativeReconnectPlanDebug(
          reason = NativeMobileRetryableReason.ACK_DEADLINE,
          failureOrdinal = 0,
          delayMillis = 1_000L,
          stage = NativeReconnectStage.WAITING,
        ),
        runtime.reconnectPlanForTesting(),
      )
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun firstBootstrapRetryFailureDoesNotReturnSuccessAfterSchedulerRejection() {
    val executor = CapturingScheduledExecutor().apply { rejectDelayedTasks = true }
    val fakeSession = FakeSession().apply {
      nextLiveBufferFailure.set(
        NativeMobileRetryableException(NativeMobileRetryableReason.TRANSPORT),
      )
    }
    val runtime = runtime(executor, fakeSession)
    try {
      runtime.openSession()

      val error = assertThrows(VeilMobileRuntimeException::class.java) {
        runtime.connect("https://access.example")
      }

      assertEquals("E_VEIL_SYNC", error.code)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertNull(runtime.reconnectPlanForTesting())
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun reconnectSchedulerRejectionIsTerminalAndCannotLeaveAConnectingOwner() {
    val executor = CapturingScheduledExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_FOR_REPLAY)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("36", "Rejected", "37", "rejected", false)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      executor.rejectDelayedTasks = true
      val result = DirectTextSendCapture()

      runtime.sendDirectText(conversation.conversationId, generation, "scheduler-rejected", result)

      assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())
      val failed = runtime.snapshot()
      assertEquals(NativeConnectionState.ERROR, failed.connectionState)
      assertNull(failed.binding)
      assertNull(failed.directGeneration)
      assertNull(runtime.reconnectPlanForTesting())
      executor.runCapturedDelayedTask()
      assertEquals(1, fakeSession.plainConnectCount)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundRevokesPendingDirectTextAndLatePreKeyResponseOnlyWipesItsBody() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.NEEDS_PRE_KEY)
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val lateBody = "late-peer-prekey-after-background".toByteArray()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val result = DirectTextSendCapture()
      runtime.sendDirectText(
        conversation.conversationId,
        generation,
        "wipe this pending user plaintext at the lifecycle boundary",
        result,
      )
      val pendingCall = transport.calls.last()
      assertEquals(1, fakeSession.directTextSendCount)
      assertEquals(1, transport.pendingCount())

      runtime.lockForBackground()

      assertTrue(pendingCall.cancelled.get())
      assertEquals(NativeDirectTextSendResult.UNAVAILABLE, result.await())
      assertEquals(1, result.completionCount.get())
      assertTrue(fakeSession.directTextPlaintextReferences.single().all { it == 0.toByte() })

      transport.completeNext(NativeDirectHttpResult.Success(lateBody))
      awaitRuntimeIdle(runtime)

      assertTrue(lateBody.all { it == 0.toByte() })
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(1, fakeSession.directTextSendCount)
      assertEquals(1, result.completionCount.get())
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
      assertNull(runtime.snapshot().directGeneration)
    } finally {
      lateBody.fill(0)
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun duplicateDirectTextIntentIsDeniedWhileTheExactFirstActionOwnsPreKeyAuthority() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.NEEDS_PRE_KEY)
      directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED)
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val first = DirectTextSendCapture()
      runtime.sendDirectText(conversation.conversationId, generation, "first intent", first)

      val duplicate = DirectTextSendCapture()
      runtime.sendDirectText(conversation.conversationId, generation, "duplicate tap", duplicate)

      assertEquals(NativeDirectTextSendResult.UNAVAILABLE, duplicate.await())
      assertEquals(1, duplicate.completionCount.get())
      assertEquals(0, first.completionCount.get())
      assertEquals(1, fakeSession.directTextSendCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(requestCount + 1, transport.requests.size)
      assertEquals(1, transport.pendingCount())

      transport.completeNext(
        NativeDirectHttpResult.Success("peer-prekey-for-the-first-intent-only".toByteArray()),
      )
      awaitRuntimeIdle(runtime)

      assertEquals(NativeDirectTextSendResult.ACCEPTED, first.await())
      assertEquals(1, first.completionCount.get())
      assertEquals(2, fakeSession.directTextSendCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(requestCount + 1, transport.requests.size)
      assertTrue(
        fakeSession.directTextPlaintextReferences.all { reference ->
          reference.all { it == 0.toByte() }
        },
      )
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun peerPreKeyStartsOnlyFromOneExplicitExactGenerationAction() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestsBeforeAction = transport.requests.size
      val signaturesBeforeAction = fakeSession.signedRequestCopies.size

      // Directory publication, selection/projection, and the initial live
      // replay are all non-authoritative hints and never fetch a peer prekey.
      publishDirectMessagesForTest(runtime, conversation.conversationId)
      assertEquals(0, fakeSession.peerPreKeyRequestCount)
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(requestsBeforeAction, transport.requests.size)

      val first = DirectSessionActionCapture()
      runtime.establishDirectSession(conversation.conversationId, generation, first)

      assertEquals(1, fakeSession.directSendReadinessCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(signaturesBeforeAction + 1, fakeSession.signedRequestCopies.size)
      assertEquals(requestsBeforeAction + 1, transport.requests.size)
      assertEquals(1, transport.pendingCount())
      val request = transport.requests.last()
      assertEquals(NativeDirectHttpMethod.GET, request.method)
      assertEquals("/v1/prekeys/${"cd".repeat(32)}", request.requestTarget)
      assertEquals(NativeDirectHttpLimits.PREKEY_BYTES, request.responseLimitBytes)
      assertTrue(request.body.isEmpty())
      assertTrue(transport.calls.last().started.get())

      val duplicate = DirectSessionActionCapture()
      runtime.establishDirectSession(conversation.conversationId, generation, duplicate)
      assertEquals(NativeDirectSessionActionResult.Unavailable, duplicate.await())
      assertEquals(1, duplicate.completionCount.get())
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(signaturesBeforeAction + 1, fakeSession.signedRequestCopies.size)
      assertEquals(requestsBeforeAction + 1, transport.requests.size)

      val response = "authenticated-peer-prekey-bundle".toByteArray()
      transport.completeNext(NativeDirectHttpResult.Success(response))
      awaitRuntimeIdle(runtime)

      val success = first.await() as NativeDirectSessionActionResult.Success
      assertEquals(NativeDirectPreKeyInstallStatus.ESTABLISHED, success.install.status)
      assertEquals(1, first.completionCount.get())
      assertTrue(response.all { it == 0.toByte() })
      assertEquals(1, fakeSession.peerPreKeyInstallCount)
      assertEquals(
        listOf(conversation.conversationId),
        fakeSession.peerPreKeyInstalledConversationIds,
      )
      assertTrue(runtime.snapshot().directoryReady)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun alreadyEstablishedNativeReadinessNeverPreparesSignsOrStartsARequest() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      fakeSession.directSendReadiness = NativeDirectSendReadiness.READY
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val result = DirectSessionActionCapture()

      runtime.establishDirectSession(conversation.conversationId, generation, result)

      val success = result.await() as NativeDirectSessionActionResult.Success
      assertEquals(NativeDirectPreKeyInstallStatus.ALREADY_ESTABLISHED, success.install.status)
      assertEquals(1, result.completionCount.get())
      assertEquals(1, fakeSession.directSendReadinessCount)
      assertEquals(0, fakeSession.peerPreKeyRequestCount)
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(signatureCount, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount, transport.requests.size)
      assertTrue(runtime.snapshot().directoryReady)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun readyRaceAfterSuccessfulPrepareRevokesRetainedUnsignedCapability() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      becomeReadyAfterPeerPreKeyPrepare = true
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val result = DirectSessionActionCapture()

      runtime.establishDirectSession(conversation.conversationId, generation, result)

      assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(1, fakeSession.directSendReadinessCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(signatureCount, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount, transport.requests.size)
      assertEquals(0, fakeSession.preparedRequestCount())
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertNull(runtime.snapshot().directGeneration)
      assertFalse(runtime.snapshot().directoryReady)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun prepareBridgeFailureAfterRetainAndReadyRevokesWholeLease() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      becomeReadyAfterPeerPreKeyPrepare = true
      failPeerPreKeyPrepareAfterRetain = true
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val result = DirectSessionActionCapture()

      runtime.establishDirectSession(conversation.conversationId, generation, result)

      assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(1, fakeSession.directSendReadinessCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(signatureCount, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount, transport.requests.size)
      assertEquals(0, fakeSession.preparedRequestCount())
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertNull(runtime.snapshot().directGeneration)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun kotlinValidationFailureAfterPrepareRevokesCapabilityBeforeSigning() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      corruptPeerPreKeyMethodAfterRetain = true
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val result = DirectSessionActionCapture()

      runtime.establishDirectSession(conversation.conversationId, generation, result)

      assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(1, fakeSession.directSendReadinessCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(signatureCount, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount, transport.requests.size)
      assertEquals(0, fakeSession.preparedRequestCount())
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertNull(runtime.snapshot().directGeneration)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun signingFailureAfterPrepareRevokesRetainedCapability() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      failPeerPreKeySign = true
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val result = DirectSessionActionCapture()

      runtime.establishDirectSession(conversation.conversationId, generation, result)

      assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(1, fakeSession.directSendReadinessCount)
      assertEquals(1, fakeSession.peerPreKeyRequestCount)
      assertEquals(signatureCount, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount, transport.requests.size)
      assertEquals(0, fakeSession.preparedRequestCount())
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().directGeneration)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun callCreationFailureAfterSignatureRevokesLeaseWithoutStartingGet() {
    val executor = daemonExecutor()
    val transport = ControllableDirectTransport()
    val fakeSession = FakeSession()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val callCount = transport.calls.size
      val capturedBodyCount = transport.capturedBodies.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val result = DirectSessionActionCapture()
      transport.failNextCreation()

      runtime.establishDirectSession(conversation.conversationId, generation, result)

      assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(signatureCount + 1, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount, transport.requests.size)
      assertEquals(callCount, transport.calls.size)
      assertEquals(capturedBodyCount, transport.capturedBodies.size)
      assertEquals(0, fakeSession.preparedRequestCount())
      assertEquals(1, fakeSession.directLeaseCancellations)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().directGeneration)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun lateNativeAlreadyEstablishedResultWipesBodyWithoutKotlinRatchetMutation() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply {
      peerPreKeyInstallStatus = NativeDirectPreKeyInstallStatus.ALREADY_ESTABLISHED
    }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val response = "late-ready-peer-prekey-response".toByteArray()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val result = DirectSessionActionCapture()
      runtime.establishDirectSession(conversation.conversationId, generation, result)

      transport.completeNext(NativeDirectHttpResult.Success(response))
      awaitRuntimeIdle(runtime)

      val success = result.await() as NativeDirectSessionActionResult.Success
      assertEquals(NativeDirectPreKeyInstallStatus.ALREADY_ESTABLISHED, success.install.status)
      assertTrue(response.all { it == 0.toByte() })
      assertEquals(1, fakeSession.peerPreKeyInstallCount)
      assertEquals(NativeConnectionState.CONNECTED, runtime.snapshot().connectionState)
      assertTrue(runtime.snapshot().directoryReady)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun wrongConversationGenerationAndUnavailableReadinessStayOpaqueAndDoNoWork() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val requestCount = transport.requests.size
      val signatureCount = fakeSession.signedRequestCopies.size
      val denied = listOf(
        "550e8400-e29b-41d4-a716-446655440099" to generation,
        conversation.conversationId to generation + 1L,
        "not-a-canonical-conversation" to generation,
      )
      denied.forEach { (conversationId, expectedGeneration) ->
        val result = DirectSessionActionCapture()
        runtime.establishDirectSession(conversationId, expectedGeneration, result)
        assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
        assertEquals(1, result.completionCount.get())
      }
      assertEquals(0, fakeSession.directSendReadinessCount)

      fakeSession.directSendReadiness = NativeDirectSendReadiness.UNAVAILABLE
      val unavailable = DirectSessionActionCapture()
      runtime.establishDirectSession(conversation.conversationId, generation, unavailable)
      assertEquals(NativeDirectSessionActionResult.Unavailable, unavailable.await())
      assertEquals(1, fakeSession.directSendReadinessCount)
      assertEquals(0, fakeSession.peerPreKeyRequestCount)
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(signatureCount, fakeSession.signedRequestCopies.size)
      assertEquals(requestCount, transport.requests.size)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundCancelsExactPeerPreKeyAndLateResponseOnlyGetsWiped() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val lateBody = "late-background-peer-prekey-bundle".toByteArray()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val result = DirectSessionActionCapture()
      runtime.establishDirectSession(conversation.conversationId, generation, result)
      val pendingCall = transport.calls.last()

      runtime.lockForBackground()

      assertTrue(pendingCall.cancelled.get())
      assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
      assertEquals(1, result.completionCount.get())
      transport.completeNext(NativeDirectHttpResult.Success(lateBody))
      awaitRuntimeIdle(runtime)
      assertTrue(lateBody.all { it == 0.toByte() })
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(1, result.completionCount.get())
      assertEquals(NativeSessionState.LOCKED, runtime.snapshot().sessionState)
      assertNull(runtime.snapshot().directGeneration)
    } finally {
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundWinningAfterHandlerPrecheckPreventsNativePeerPreKeyInstall() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val installBoundaryEntered = CountDownLatch(1)
    val releaseInstallBoundary = CountDownLatch(1)
    val runtime = runtime(
      executor,
      fakeSession,
      directTransport = transport,
      peerPreKeyInstallBoundary = {
        installBoundaryEntered.countDown()
        check(releaseInstallBoundary.await(5, TimeUnit.SECONDS)) {
          "peer-prekey install boundary timed out"
        }
      },
    )
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val response = "prechecked-then-background-revoked-bundle".toByteArray()
    val result = DirectSessionActionCapture()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      runtime.establishDirectSession(conversation.conversationId, generation, result)
      transport.completeNext(NativeDirectHttpResult.Success(response))
      assertTrue(
        "peer-prekey handler did not pass its first lifecycle check",
        installBoundaryEntered.await(5, TimeUnit.SECONDS),
      )

      runtime.lockForBackground()

      assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      releaseInstallBoundary.countDown()
      awaitRuntimeIdle(runtime)
      assertTrue(response.all { it == 0.toByte() })
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(1, result.completionCount.get())
      assertNull(runtime.snapshot().directGeneration)
    } finally {
      releaseInstallBoundary.countDown()
      executor.shutdownNow()
    }
  }

  @Test
  fun backgroundDuringPeerPreKeyCallCreationCancelsBeforeItCanStart() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val callCreated = CountDownLatch(1)
    val releaseCreation = CountDownLatch(1)
    val createdCalls = AtomicInteger(0)
    val transport = ControllableDirectTransport {
      if (createdCalls.incrementAndGet() == 4) {
        callCreated.countDown()
        check(releaseCreation.await(5, TimeUnit.SECONDS)) {
          "peer-prekey call creation barrier timed out"
        }
      }
    }
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val action = DirectSessionActionCapture()
    var starter: Thread? = null
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val activeStarter = thread(name = "peer-prekey-create-before-background") {
        runtime.establishDirectSession(conversation.conversationId, generation, action)
      }
      starter = activeStarter
      assertTrue("peer-prekey call was not created", callCreated.await(5, TimeUnit.SECONDS))
      val unstarted = transport.calls.last()
      assertFalse(unstarted.started.get())
      val networkRequestCount = transport.requests.size

      runtime.lockForBackground()
      releaseCreation.countDown()
      activeStarter.join(5_000)

      assertFalse("stale peer-prekey starter did not finish", activeStarter.isAlive)
      assertTrue(unstarted.cancelled.get())
      assertFalse(unstarted.started.get())
      assertEquals(networkRequestCount, transport.requests.size)
      assertEquals(NativeDirectSessionActionResult.Unavailable, action.await())
      assertEquals(1, action.completionCount.get())
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
    } finally {
      releaseCreation.countDown()
      starter?.join(5_000)
      executor.shutdownNow()
    }
  }

  @Test
  fun reconnectCancelsOldPeerPreKeyGenerationAndRejectsItsLateBody() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val staleBody = "superseded-peer-prekey-bundle".toByteArray()
    try {
      val oldGeneration = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val oldResult = DirectSessionActionCapture()
      runtime.establishDirectSession(conversation.conversationId, oldGeneration, oldResult)
      val staleCall = transport.calls.last()

      runtime.connect("https://access.example")

      assertTrue(staleCall.cancelled.get())
      assertEquals(NativeDirectSessionActionResult.Unavailable, oldResult.await())
      val newGeneration = checkNotNull(runtime.snapshot().directGeneration)
      assertTrue(newGeneration > oldGeneration)
      transport.completeNext(NativeDirectHttpResult.Success(staleBody))
      awaitRuntimeIdle(runtime)
      assertTrue(staleBody.all { it == 0.toByte() })
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(1, oldResult.completionCount.get())

      val staleSelection = DirectSessionActionCapture()
      runtime.establishDirectSession(
        conversation.conversationId,
        oldGeneration,
        staleSelection,
      )
      assertEquals(NativeDirectSessionActionResult.Unavailable, staleSelection.await())
      assertEquals(NativeOwnPreKeyState.CHECKING, runtime.snapshot().ownPreKeyState)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun peerPreKeyTransportFailureIsOpaqueAndRevokesTheUncertainLease() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession()
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val result = DirectSessionActionCapture()
      runtime.establishDirectSession(conversation.conversationId, generation, result)

      transport.completeNext(NativeDirectHttpResult.Failure(NativeDirectHttpFailure.NETWORK))
      awaitRuntimeIdle(runtime)

      assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
      assertEquals(1, result.completionCount.get())
      assertEquals(0, fakeSession.peerPreKeyInstallCount)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().binding)
      assertNull(runtime.snapshot().directGeneration)
      assertEquals(1, fakeSession.directLeaseCancellations)
    } finally {
      runtime.lockSession()
      executor.shutdownNow()
    }
  }

  @Test
  fun peerPreKeyInstallFailureWipesBodyAndFailsClosedWithoutDetail() {
    val executor = daemonExecutor()
    val fakeSession = FakeSession().apply { failPeerPreKeyInstall = true }
    val transport = ControllableDirectTransport()
    val runtime = runtime(executor, fakeSession, directTransport = transport)
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val rejectedBody = "rejected-peer-prekey-bundle".toByteArray()
    try {
      val generation = completeDirectReadyBootstrap(runtime, fakeSession, transport, conversation)
      val result = DirectSessionActionCapture()
      runtime.establishDirectSession(conversation.conversationId, generation, result)

      transport.completeNext(NativeDirectHttpResult.Success(rejectedBody))
      awaitRuntimeIdle(runtime)

      assertTrue(rejectedBody.all { it == 0.toByte() })
      assertEquals(NativeDirectSessionActionResult.Unavailable, result.await())
      assertEquals(1, fakeSession.peerPreKeyInstallCount)
      assertEquals(NativeConnectionState.ERROR, runtime.snapshot().connectionState)
      assertNull(runtime.snapshot().directGeneration)
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

    val replay = MobileDirectLiveReplayProgress(
      consumed = 64u,
      projectionChanged = true,
      needsImmediatePump = true,
      outboxReplayRequired = false,
      ready = false,
    ).toNativeDirectLiveReplayProgress()
    assertEquals(64L, replay.consumed)
    assertTrue(replay.projectionChanged)
    assertTrue(replay.needsImmediatePump)
    assertFalse(replay.outboxReplayRequired)
    assertFalse(replay.ready)
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
  fun publicDirectoryProjectionIsAllowlistedAndRequiresExactReadyAuthority() {
    val conversation = directConversation("10", "Alice", "11", "alice", needsPreKey = true)
    val ready = readyPublicDirectorySnapshot(listOf(conversation))

    val publication = ready.toPublicDirectDirectoryPublication()
    assertTrue(publication.ready)
    assertEquals(1, publication.conversations.size)
    assertEquals(
      setOf("conversationId", "name", "peerUserId", "peerUsername"),
      PublicDirectConversationView::class.java.declaredFields.map { it.name }.toSet(),
    )
    assertEquals(conversation.conversationId, publication.conversations.single().conversationId)
    assertEquals("Alice", publication.conversations.single().name)
    assertEquals("alice", publication.conversations.single().peerUsername)
    assertFalse(publication.toString().contains("needsPreKey"))
    assertFalse(publication.toString().contains("Alice"))
    assertFalse(publication.conversations.single().toString().contains("Alice"))

    val lifecycleDisagreements = listOf(
      ready.copy(identityExists = false),
      ready.copy(sessionState = NativeSessionState.LOCKED),
      ready.copy(connectionState = NativeConnectionState.DISCONNECTED),
      ready.copy(directoryReady = false),
      ready.copy(secureSyncState = NativeSecureSyncState.SYNCING_HISTORY),
      ready.copy(ownPreKeyState = NativeOwnPreKeyState.CHECKING),
      ready.copy(directDirectoryState = NativeDirectDirectoryState.SYNCING),
      ready.copy(directHistoryState = NativeDirectHistoryState.SYNCING),
      ready.copy(binding = null),
    )
    lifecycleDisagreements.forEach { snapshot ->
      val denied = snapshot.toPublicDirectDirectoryPublication()
      assertFalse(denied.ready)
      assertTrue(denied.conversations.isEmpty())
    }
  }

  @Test
  fun publicDirectoryProjectionRejectsMalformedRowsWithoutPublishingAPrefix() {
    val valid = directConversation("10", "Alice", "11", "alice", needsPreKey = false)
    val invalidDirectories = listOf(
      listOf(valid, valid.copy(peerUsername = "other")),
      listOf(
        valid,
        directConversation("09", "Earlier", "12", "earlier", needsPreKey = false),
      ),
      listOf(valid.copy(conversationId = "00000000-0000-0000-0000-000000000000")),
      listOf(valid.copy(peerUserId = valid.peerUserId.uppercase())),
      listOf(valid.copy(peerUserId = "550e8400-e29b-41d4-a716-446655440001")),
      listOf(valid.copy(name = "Alice\nAdmin")),
      listOf(valid.copy(peerUsername = "a".repeat(129))),
      listOf(valid.copy(name = "\uD800")),
    )

    invalidDirectories.forEach { conversations ->
      val denied = readyPublicDirectorySnapshot(conversations)
        .toPublicDirectDirectoryPublication()
      assertFalse(denied.ready)
      assertTrue(denied.conversations.isEmpty())
    }

    val exactFourByteName = "\uD83E\uDD80".repeat(64)
    assertTrue(
      readyPublicDirectorySnapshot(listOf(valid.copy(name = exactFourByteName)))
        .toPublicDirectDirectoryPublication()
        .ready,
    )
    assertFalse(
      readyPublicDirectorySnapshot(listOf(valid.copy(name = "$exactFourByteName+")))
        .toPublicDirectDirectoryPublication()
        .ready,
    )
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

    assertEquals(
      NativeDirectSendReadiness.READY,
      MobileDirectSendReadiness.READY.toNativeDirectSendReadiness(),
    )
    assertEquals(
      NativeDirectSendReadiness.NEEDS_PRE_KEY,
      MobileDirectSendReadiness.NEEDS_PRE_KEY.toNativeDirectSendReadiness(),
    )
    assertEquals(
      NativeDirectSendReadiness.UNAVAILABLE,
      MobileDirectSendReadiness.UNAVAILABLE.toNativeDirectSendReadiness(),
    )

    assertEquals(1L, 1.0.toSafeDirectGenerationOrNull())
    assertEquals(9_007_199_254_740_991L, 9_007_199_254_740_991.0.toSafeDirectGenerationOrNull())
    assertNull(0.0.toSafeDirectGenerationOrNull())
    assertNull(1.5.toSafeDirectGenerationOrNull())
    assertNull(Double.NaN.toSafeDirectGenerationOrNull())
    assertNull(Double.POSITIVE_INFINITY.toSafeDirectGenerationOrNull())
  }

  private fun runtime(
    executor: ScheduledExecutorService,
    session: FakeSession,
    passStore: NodeAccessPassStore = deterministicPassStore(),
    vault: NativeIdentityVaultAccess = FakeVault(),
    markForeground: Boolean = true,
    cancellationFactory: NativeConnectCancellationFactory =
      NativeConnectCancellationFactory { FakeCancellation() },
    directTransport: NativeDirectHttpExecutor = PassiveDirectTransport(),
    directLivePollIntervalMillis: Long = 60_000L,
    reconnectJitterMillis: (Long) -> Long = { capMillis -> capMillis },
    directBootstrapOwnerBoundary: () -> Unit = {},
    peerPreKeyInstallBoundary: () -> Unit = {},
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
      directLivePollIntervalMillis = directLivePollIntervalMillis,
      reconnectJitterMillis = reconnectJitterMillis,
      directBootstrapOwnerBoundary = directBootstrapOwnerBoundary,
      peerPreKeyInstallBoundary = peerPreKeyInstallBoundary,
    ).also { runtime ->
      if (markForeground) runtime.markForeground()
    }

  private fun deterministicPassStore(): NodeAccessPassStore = NodeAccessPassStore(
    clockMillis = { 1_000L },
    randomBytes = { output -> output.fill(0x44) },
  )

  private fun daemonExecutor(): ScheduledExecutorService =
    Executors.newSingleThreadScheduledExecutor { operation ->
    Thread(operation, "veil-runtime-test").apply { isDaemon = true }
  }

  private class CapturingScheduledExecutor(
    private val captureImmediateTasks: Boolean = false,
  ) : ScheduledThreadPoolExecutor(
    1,
    { operation -> Thread(operation, "veil-runtime-capturing-test").apply { isDaemon = true } },
  ) {
    private val delayedTask = AtomicReference<Runnable?>()
    private val delayedSchedules = AtomicInteger(0)
    private val immediateTasks = ConcurrentLinkedQueue<Runnable>()
    private val immediateSchedules = AtomicInteger(0)
    private val executeNextDelayedTaskInline = AtomicBoolean(false)
    private val executeNextImmediateTaskInline = AtomicBoolean(false)
    @Volatile var rejectDelayedTasks = false
    @Volatile var rejectImmediateTasks = false

    override fun schedule(command: Runnable, delay: Long, unit: TimeUnit): ScheduledFuture<*> {
      if (delay <= 0L) {
        if (!captureImmediateTasks) return super.schedule(command, delay, unit)
        if (rejectImmediateTasks) throw RejectedExecutionException("synthetic immediate scheduler rejection")
        immediateSchedules.incrementAndGet()
        if (executeNextImmediateTaskInline.getAndSet(false)) {
          command.run()
        } else {
          immediateTasks.add(command)
        }
        return super.schedule({}, 1L, TimeUnit.DAYS)
      }
      if (rejectDelayedTasks) throw RejectedExecutionException("synthetic delayed scheduler rejection")
      delayedSchedules.incrementAndGet()
      delayedTask.set(command)
      if (executeNextDelayedTaskInline.getAndSet(false)) command.run()
      return super.schedule({}, 1L, TimeUnit.DAYS)
    }

    fun runCapturedDelayedTask() {
      checkNotNull(delayedTask.get()).run()
    }

    fun runCapturedImmediateTask() {
      checkNotNull(immediateTasks.poll()).run()
    }

    fun runNextDelayedTaskInline() {
      check(executeNextDelayedTaskInline.compareAndSet(false, true))
    }

    fun runNextImmediateTaskInline() {
      check(executeNextImmediateTaskInline.compareAndSet(false, true))
    }

    fun delayedScheduleCount(): Int = delayedSchedules.get()

    fun immediateScheduleCount(): Int = immediateSchedules.get()
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

  private fun completeDirectReadyBootstrap(
    runtime: VeilMobileRuntime,
    session: FakeSession,
    transport: ControllableDirectTransport,
    conversation: NativeDirectConversationInstall,
  ): Long {
    session.directoryInstalls.clear()
    session.directoryInstalls.add(
      NativeDirectDirectoryInstall(listOf(conversation), directoryComplete = true),
    )
    runtime.openSession()
    runtime.connect("https://access.example")
    completeOwnPreKeyBootstrap(runtime, transport)
    transport.completeNext(
      NativeDirectHttpResult.Success("authenticated-explicit-prekey-directory".toByteArray()),
    )
    awaitRuntimeIdle(runtime)
    val ready = runtime.snapshot()
    assertTrue(ready.directoryReady)
    assertEquals(NativeDirectHistoryState.SYNCHRONIZED, ready.directHistoryState)
    return checkNotNull(ready.directGeneration)
  }

  private fun establishWaitingReconnect(
    runtime: VeilMobileRuntime,
    session: FakeSession,
    transport: ControllableDirectTransport,
    conversation: NativeDirectConversationInstall,
  ) {
    val generation = completeDirectReadyBootstrap(runtime, session, transport, conversation)
    session.directTextSendOutcomes.add(NativeDirectTextSendOutcome.ACCEPTED_FOR_REPLAY)
    val result = DirectTextSendCapture()
    runtime.sendDirectText(conversation.conversationId, generation, "durable-before-cancel", result)
    assertEquals(NativeDirectTextSendResult.ACCEPTED, result.await())
    assertEquals(NativeReconnectStage.WAITING, runtime.reconnectPlanForTesting()?.stage)
  }

  private class DirectSessionActionCapture : NativeDirectSessionActionCallback {
    private val completed = CountDownLatch(1)
    private val value = AtomicReference<NativeDirectSessionActionResult?>()
    val completionCount = AtomicInteger(0)

    override fun onComplete(result: NativeDirectSessionActionResult) {
      completionCount.incrementAndGet()
      value.set(result)
      completed.countDown()
    }

    fun await(): NativeDirectSessionActionResult {
      assertTrue("Direct-session action did not complete", completed.await(5, TimeUnit.SECONDS))
      return checkNotNull(value.get())
    }
  }

  private class DirectTextSendCapture : NativeDirectTextSendCallback {
    private val completed = CountDownLatch(1)
    private val value = AtomicReference<NativeDirectTextSendResult?>()
    val completionCount = AtomicInteger(0)

    override fun onComplete(result: NativeDirectTextSendResult) {
      completionCount.incrementAndGet()
      value.set(result)
      completed.countDown()
    }

    fun await(): NativeDirectTextSendResult {
      assertTrue("Direct text send did not complete", completed.await(5, TimeUnit.SECONDS))
      return checkNotNull(value.get())
    }
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

  private fun readyPublicDirectorySnapshot(
    conversations: List<NativeDirectConversationInstall>,
  ): VeilMobileRuntimeSnapshot = VeilMobileRuntimeSnapshot(
    identityExists = true,
    runtimeRevision = 1L,
    directGeneration = 1L,
    directContentRevision = 0L,
    sessionState = NativeSessionState.OPEN,
    connectionState = NativeConnectionState.CONNECTED,
    directoryReady = true,
    secureSyncState = NativeSecureSyncState.HISTORY_SYNCHRONIZED,
    ownPreKeyState = NativeOwnPreKeyState.PUBLISHED,
    directDirectoryState = NativeDirectDirectoryState.SYNCHRONIZED,
    directHistoryState = NativeDirectHistoryState.SYNCHRONIZED,
    directConversations = conversations,
    binding = PublicAuthenticatedBinding(
      canonicalServerOrigin = "https://veil.example:443",
      userId = "550e8400-e29b-41d4-a716-446655440001",
    ),
    pendingAccessPass = null,
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
    @Volatile var authenticatedUserId = USER_ID
    @Volatile var storedReconnectTarget: NativeMobileReconnectTarget? = null
    @Volatile var storedReconnectTargetFailure: Throwable? = null
    @Volatile var storedReconnectTargetLoadCount = 0
    @Volatile var storedReconnectTargetLoadEntered: CountDownLatch? = null
    @Volatile var storedReconnectTargetLoadRelease: CountDownLatch? = null
    @Volatile var plainConnectCount = 0
    @Volatile var accessPassConnectCount = 0
    val queuedConnectFailures = ConcurrentLinkedQueue<Throwable>()
    @Volatile var blockPlainConnectOnCount: Int? = null
    @Volatile var succeedBlockedPlainConnectAfterCancellation = false
    val blockedPlainConnectEntered = CountDownLatch(1)
    var closed = false
    var directLeaseCancellations = 0
    @Volatile var directSyncBeginCount = 0
    var directLeaseUserOverride: String? = null
    var directoryRequestCount = 0
    var historyRequestCount = 0
    var liveBufferPumpCount = 0
    @Volatile var liveReplayPumpCount = 0
    @Volatile var projectionChangeOnOrAfterReplayPump: Int? = null
    @Volatile var failLiveReplayOnOrAfterPump: Int? = null
    val nextLiveBufferFailure = AtomicReference<Throwable?>()
    val nextLiveReplayFailure = AtomicReference<Throwable?>()
    @Volatile var outboxReplayPumpCount = 0
    @Volatile var failOutboxReplayPump = false
    val nextOutboxReplayFailure = AtomicReference<Throwable?>()
    @Volatile var outboxReplayComplete = false
    @Volatile var blockOutboxReplayOnPump: Int? = null
    @Volatile var outboxReplayEntered: CountDownLatch? = null
    @Volatile var outboxReplayRelease: CountDownLatch? = null
    var directProjectionCount = 0
    @Volatile var directProjection = NativeDirectMessageProjection(
      NativeDirectMessageProjectionAvailability.UNAVAILABLE,
      emptyList(),
    )
    @Volatile var directProjectionEntered: CountDownLatch? = null
    @Volatile var directProjectionRelease: CountDownLatch? = null
    @Volatile var directProjectionFailure: Throwable? = null
    @Volatile var directReplayEntered: CountDownLatch? = null
    @Volatile var directReplayRelease: CountDownLatch? = null
    var failLiveBufferPump = false
    var failLiveReplayPump = false
    var historySynchronized = false
    var ownPreKeyRequestCount = 0
    var ownPreKeyInstallCount = 0
    var directSendReadinessCount = 0
    @Volatile var directSendReadiness = NativeDirectSendReadiness.NEEDS_PRE_KEY
    @Volatile var directTextSendCount = 0
    val directTextSendOutcomes = ArrayDeque<NativeDirectTextSendOutcome>()
    val directTextPlaintextReferences = CopyOnWriteArrayList<ByteArray>()
    val directTextPlaintextCopies = CopyOnWriteArrayList<ByteArray>()
    var peerPreKeyRequestCount = 0
    var peerPreKeyInstallCount = 0
    @Volatile var peerPreKeyInstallStatus = NativeDirectPreKeyInstallStatus.ESTABLISHED
    @Volatile var failPeerPreKeyInstall = false
    @Volatile var failPeerPreKeyPrepareAfterRetain = false
    @Volatile var failPeerPreKeySign = false
    @Volatile var becomeReadyAfterPeerPreKeyPrepare = false
    @Volatile var corruptPeerPreKeyMethodAfterRetain = false
    val peerPreKeyInstalledResponseCopies = CopyOnWriteArrayList<ByteArray>()
    val peerPreKeyInstalledConversationIds = CopyOnWriteArrayList<String>()
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
    val liveReplayProgresses = ArrayDeque<NativeDirectLiveReplayProgress>()
    val outboxReplayProgresses = ArrayDeque<NativeDirectOutboxReplayProgress>()
    val lifecycleEvents = CopyOnWriteArrayList<String>()
    val connectStarted = CountDownLatch(1)
    val closedDuringConnect = AtomicBoolean(false)
    private val inConnect = AtomicBoolean(false)

    override fun mobileReconnectTarget(): NativeMobileReconnectTarget? {
      storedReconnectTargetLoadCount += 1
      storedReconnectTargetLoadEntered?.countDown()
      storedReconnectTargetLoadRelease?.let { release ->
        check(release.await(5, TimeUnit.SECONDS)) { "stored reconnect target load timed out" }
      }
      storedReconnectTargetFailure?.let { throw it }
      return storedReconnectTarget
    }

    override fun connect(
      websocketUrl: String,
      canonicalOrigin: String,
      cancellation: NativeConnectCancellation,
    ): PublicAuthenticatedBinding {
      plainConnectCount += 1
      awaitDynamicPlainConnectCancellation(cancellation)
      awaitCancellationIfRequested(cancellation)
      queuedConnectFailures.poll()?.let { throw it }
      connectFailure?.let { throw it }
      this.websocketUrl = websocketUrl
      this.canonicalOrigin = canonicalOrigin
      return PublicAuthenticatedBinding(canonicalOrigin, authenticatedUserId)
    }

    override fun connectWithNodeAccessPass(
      websocketUrl: String,
      canonicalOrigin: String,
      nodeAccessPass: ByteArray,
      cancellation: NativeConnectCancellation,
    ): PublicAuthenticatedBinding {
      accessPassConnectCount += 1
      awaitCancellationIfRequested(cancellation)
      queuedConnectFailures.poll()?.let { throw it }
      connectFailure?.let { throw it }
      this.websocketUrl = websocketUrl
      this.canonicalOrigin = canonicalOrigin
      lastAccessPass = nodeAccessPass.copyOf()
      return PublicAuthenticatedBinding(canonicalOrigin, authenticatedUserId)
    }

    override fun beginDirectSync(): NativeDirectSyncLease {
      directSyncBeginCount += 1
      historySynchronized = false
      outboxReplayComplete = false
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
      nextLiveBufferFailure.getAndSet(null)?.let { throw it }
      if (failLiveBufferPump) throw IllegalStateException("synthetic terminal live buffer")
      return NativeDirectLiveBufferProgress(
        bufferedEvents = 0,
        historySynchronized = historySynchronized,
      )
    }

    override fun replayDirectLiveEvents(leaseToken: String): NativeDirectLiveReplayProgress {
      liveReplayPumpCount += 1
      directReplayEntered?.countDown()
      directReplayRelease?.let { release ->
        check(release.await(5, TimeUnit.SECONDS)) { "synthetic Direct live replay timed out" }
      }
      nextLiveReplayFailure.getAndSet(null)?.let { throw it }
      if (
        failLiveReplayPump ||
        failLiveReplayOnOrAfterPump?.let { liveReplayPumpCount >= it } == true
      ) throw IllegalStateException("synthetic terminal live replay")
      check(historySynchronized) { "synthetic live replay started before history completion" }
      if (
        projectionChangeOnOrAfterReplayPump?.let { liveReplayPumpCount >= it } == true
      ) {
        projectionChangeOnOrAfterReplayPump = null
        return NativeDirectLiveReplayProgress(
          consumed = 1,
          projectionChanged = true,
          needsImmediatePump = false,
          outboxReplayRequired = false,
          ready = true,
        )
      }
      return if (liveReplayProgresses.isEmpty()) {
        NativeDirectLiveReplayProgress(
          consumed = 0,
          projectionChanged = false,
          needsImmediatePump = false,
          outboxReplayRequired = !outboxReplayComplete,
          ready = outboxReplayComplete,
        )
      } else {
        liveReplayProgresses.removeFirst()
      }
    }

    override fun replayDirectOutbox(leaseToken: String): NativeDirectOutboxReplayProgress {
      check(leaseToken == "test-direct-lease")
      outboxReplayPumpCount += 1
      if (blockOutboxReplayOnPump == outboxReplayPumpCount) {
        outboxReplayEntered?.countDown()
        outboxReplayRelease?.let { release ->
          check(release.await(5, TimeUnit.SECONDS)) { "synthetic outbox replay timed out" }
        }
      }
      nextOutboxReplayFailure.getAndSet(null)?.let { throw it }
      if (failOutboxReplayPump) throw IllegalStateException("synthetic terminal outbox replay")
      val progress = if (outboxReplayProgresses.isEmpty()) {
        NativeDirectOutboxReplayProgress(
          visited = 0,
          enqueued = 0,
          needsImmediatePump = false,
          replayComplete = true,
        )
      } else {
        outboxReplayProgresses.removeFirst()
      }
      if (progress.replayComplete) outboxReplayComplete = true
      return progress
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

    override fun directSendReadiness(
      leaseToken: String,
      conversationId: String,
    ): NativeDirectSendReadiness {
      check(leaseToken == "test-direct-lease")
      directSendReadinessCount += 1
      return directSendReadiness
    }

    override fun sendDirectText(
      leaseToken: String,
      conversationId: String,
      plaintextUtf8: ByteArray,
    ): NativeDirectTextSendOutcome {
      check(leaseToken == "test-direct-lease")
      directTextSendCount += 1
      directTextPlaintextReferences.add(plaintextUtf8)
      directTextPlaintextCopies.add(plaintextUtf8.copyOf())
      return if (directTextSendOutcomes.isEmpty()) {
        NativeDirectTextSendOutcome.UNAVAILABLE
      } else {
        directTextSendOutcomes.removeFirst()
      }
    }

    override fun prepareDirectPreKeyRequest(
      leaseToken: String,
      conversationId: String,
    ): NativeDirectRestRequest {
      check(leaseToken == "test-direct-lease")
      peerPreKeyRequestCount += 1
      val request = rememberPreparedRequest(
        NativeDirectRestRequest(
          requestToken = "test-peer-prekey-request-$peerPreKeyRequestCount",
          method = "GET",
          requestTarget = "/v1/prekeys/${"cd".repeat(32)}",
          body = byteArrayOf(),
          responseLimitBytes = NativeDirectHttpLimits.PREKEY_BYTES,
        ),
      )
      if (becomeReadyAfterPeerPreKeyPrepare) {
        directSendReadiness = NativeDirectSendReadiness.READY
      }
      if (failPeerPreKeyPrepareAfterRetain) {
        throw IllegalStateException("synthetic peer-prekey prepare failure after retain")
      }
      return if (corruptPeerPreKeyMethodAfterRetain) request.copy(method = "POST") else request
    }

    override fun installDirectPreKeyBundle(
      leaseToken: String,
      requestToken: String,
      conversationId: String,
      response: ByteArray,
    ): NativeDirectPreKeyInstall {
      check(leaseToken == "test-direct-lease")
      peerPreKeyInstallCount += 1
      peerPreKeyInstalledConversationIds.add(conversationId)
      peerPreKeyInstalledResponseCopies.add(response.copyOf())
      preparedRequests.remove(requestToken)?.body?.fill(0)
      if (failPeerPreKeyInstall) throw IllegalStateException("synthetic peer-prekey install failure")
      return NativeDirectPreKeyInstall(peerPreKeyInstallStatus)
    }

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
      if (
        prepared.requestTarget.startsWith("/v1/prekeys/") &&
        !prepared.requestTarget.endsWith("/count") &&
        (failPeerPreKeySign || directSendReadiness != NativeDirectSendReadiness.NEEDS_PRE_KEY)
      ) {
        throw IllegalStateException("synthetic peer-prekey signing denied")
      }
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

    private fun awaitDynamicPlainConnectCancellation(cancellation: NativeConnectCancellation) {
      val shouldBlock = synchronized(this) {
        if (blockPlainConnectOnCount == plainConnectCount) {
          blockPlainConnectOnCount = null
          true
        } else {
          false
        }
      }
      if (!shouldBlock) return
      val fake = cancellation as FakeCancellation
      inConnect.set(true)
      blockedPlainConnectEntered.countDown()
      check(fake.cancelled.await(5, TimeUnit.SECONDS)) {
        "dynamic reconnect cancellation timed out"
      }
      inConnect.set(false)
      if (!succeedBlockedPlainConnectAfterCancellation) {
        throw NativeMobileRetryableException(NativeMobileRetryableReason.TRANSPORT)
      }
    }

    private fun unexpectedDirectBridgeCall(): Nothing =
      throw AssertionError("Direct bridge must not be invoked by lifecycle-only runtime tests")

    private fun rememberPreparedRequest(request: NativeDirectRestRequest): NativeDirectRestRequest {
      val retained = request.copy(body = request.body.copyOf())
      check(preparedRequests.putIfAbsent(request.requestToken, retained) == null)
      return request
    }

    fun preparedRequestCount(): Int = preparedRequests.size

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
    private val failNextCreation = AtomicBoolean(false)

    override fun createCall(
      request: NativeDirectHttpRequest,
      callback: NativeDirectHttpCallback,
    ): NativeDirectHttpCall {
      if (failNextCreation.compareAndSet(true, false)) {
        throw IllegalStateException("synthetic all-or-nothing call creation failure")
      }
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

    fun failNextCreation() {
      check(failNextCreation.compareAndSet(false, true)) { "call creation failure already armed" }
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
