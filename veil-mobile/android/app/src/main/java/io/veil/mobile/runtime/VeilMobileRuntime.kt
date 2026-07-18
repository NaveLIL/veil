package io.veil.mobile.runtime

import android.content.Context
import android.os.SystemClock
import io.veil.mobile.crypto.NativeIdentityVault
import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.io.File
import java.util.UUID
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import uniffi.veil_ffi.MobileAuthenticatedBinding
import uniffi.veil_ffi.MobileConnectCancellation
import uniffi.veil_ffi.MobileDirectConversationData
import uniffi.veil_ffi.MobileDirectDirectoryPageData
import uniffi.veil_ffi.MobileDirectOwnPreKeyProgress
import uniffi.veil_ffi.MobileDirectPreKeyResult
import uniffi.veil_ffi.MobileDirectRestRequest
import uniffi.veil_ffi.MobileDirectSyncLease
import uniffi.veil_ffi.RestSignatureData
import uniffi.veil_ffi.VeilMobileSession

internal enum class NativeSessionState {
  LOCKED,
  OPENING,
  OPEN,
  CLOSING,
  ERROR,
}

internal enum class NativeConnectionState {
  DISCONNECTED,
  CONNECTING,
  CONNECTED,
  ERROR,
}

internal enum class NativeDirectDirectoryState {
  IDLE,
  SYNCING,
  SYNCHRONIZED,
  ERROR,
}

/** Native checkpoint for the authenticated device's public prekey bootstrap. */
internal enum class NativeOwnPreKeyState {
  IDLE,
  CHECKING,
  PUBLISHING,
  PUBLISHED,
  ERROR,
}

/**
 * Coarse, non-sensitive progress suitable for the React Native loading gate.
 * It deliberately reveals neither request targets nor public key material.
 */
internal enum class NativeSecureSyncState {
  IDLE,
  PUBLISHING_KEYS,
  SYNCING_DIRECTORY,
  DIRECTORY_SYNCHRONIZED,
  ERROR,
}

internal data class PublicAuthenticatedBinding(
  val canonicalServerOrigin: String,
  val userId: String,
)

/**
 * Native-only capability for one authenticated Direct sync generation.
 *
 * This type must never be added to [VeilMobileRuntimeSnapshot] or a React
 * Native bridge payload. The redacted string representation makes accidental
 * diagnostic logging less dangerous, but callers must still treat the token
 * as sensitive process-local state.
 */
internal data class NativeDirectSyncLease(
  val leaseToken: String,
  val canonicalServerOrigin: String,
  val userId: String,
) {
  override fun toString(): String =
    "NativeDirectSyncLease(canonicalServerOrigin=$canonicalServerOrigin, userId=$userId, leaseToken=[REDACTED])"
}

/** A prepared request bound to [NativeDirectSyncLease]. Never expose to JS. */
internal data class NativeDirectRestRequest(
  val requestToken: String,
  val method: String,
  val requestTarget: String,
  val body: ByteArray,
  val responseLimitBytes: Long,
) {
  override fun toString(): String =
    "NativeDirectRestRequest(" +
      "method=$method, requestTarget=[REDACTED], requestToken=[REDACTED], " +
      "body=[REDACTED], responseLimitBytes=$responseLimitBytes)"
}

/** Only the terminal publication bit crosses out of the native install call. */
internal data class NativeDirectOwnPreKeyProgress(
  val publicationComplete: Boolean,
)

/**
 * Public directory metadata copied out of a validated native install result.
 * Peer identity/signing key material is intentionally discarded at this
 * boundary: Rust has already installed it into the native session.
 */
internal data class NativeDirectConversationInstall(
  val conversationId: String,
  val name: String,
  val peerUserId: String,
  val peerUsername: String,
  val needsPreKey: Boolean,
) {
  override fun toString(): String =
    "NativeDirectConversationInstall(metadata=[REDACTED], needsPreKey=$needsPreKey)"
}

/** One validated page result; pagination state itself remains owned by Rust. */
internal data class NativeDirectDirectoryInstall(
  val conversations: List<NativeDirectConversationInstall>,
  val directoryComplete: Boolean,
)

internal enum class NativeDirectPreKeyInstallStatus {
  ESTABLISHED,
  ALREADY_ESTABLISHED,
}

internal data class NativeDirectPreKeyInstall(
  val status: NativeDirectPreKeyInstallStatus,
)

/** Signed REST headers produced by the authenticated native session. */
internal data class NativeRestSignature(
  val userId: String,
  val timestampMs: String,
  val signatureBase64: String,
) {
  override fun toString(): String =
    "NativeRestSignature(userId=$userId, timestampMs=$timestampMs, signatureBase64=[REDACTED])"
}

internal data class VeilMobileRuntimeSnapshot(
  val identityExists: Boolean,
  val sessionState: NativeSessionState,
  val connectionState: NativeConnectionState,
  val directoryReady: Boolean,
  /** Coarse bootstrap progress; contains no keys, capabilities, targets, or response bytes. */
  val secureSyncState: NativeSecureSyncState,
  /** Native-only checkpoint used to enforce prekeys-before-directory ordering. */
  val ownPreKeyState: NativeOwnPreKeyState,
  /** Native-only checkpoint state; deliberately omitted from the RN payload. */
  val directDirectoryState: NativeDirectDirectoryState,
  /** Published atomically only after the final authenticated directory page. */
  val directConversations: List<NativeDirectConversationInstall>,
  val binding: PublicAuthenticatedBinding?,
  val pendingAccessPass: PendingNodeAccessPassView?,
)

internal class VeilMobileRuntimeException(
  val code: String,
  message: String,
) : Exception(message)

internal fun interface NativeConnectCancellation : AutoCloseable {
  fun cancel()

  override fun close() = Unit
}

internal fun interface NativeConnectCancellationFactory {
  fun create(): NativeConnectCancellation
}

internal interface NativeMobileSession : AutoCloseable {
  fun connect(
    websocketUrl: String,
    canonicalOrigin: String,
    cancellation: NativeConnectCancellation,
  ): PublicAuthenticatedBinding

  fun connectWithNodeAccessPass(
    websocketUrl: String,
    canonicalOrigin: String,
    nodeAccessPass: ByteArray,
    cancellation: NativeConnectCancellation,
  ): PublicAuthenticatedBinding

  fun beginDirectSync(): NativeDirectSyncLease

  fun prepareOwnPreKeyRequest(leaseToken: String): NativeDirectRestRequest

  fun installOwnPreKeyResponse(
    leaseToken: String,
    requestToken: String,
    response: ByteArray,
  ): NativeDirectOwnPreKeyProgress

  fun prepareDirectDirectoryRequest(leaseToken: String): NativeDirectRestRequest

  fun installDirectDirectoryPage(
    leaseToken: String,
    requestToken: String,
    response: ByteArray,
  ): NativeDirectDirectoryInstall

  fun prepareDirectPreKeyRequest(
    leaseToken: String,
    conversationId: String,
  ): NativeDirectRestRequest

  fun installDirectPreKeyBundle(
    leaseToken: String,
    requestToken: String,
    conversationId: String,
    response: ByteArray,
  ): NativeDirectPreKeyInstall

  fun cancelDirectSync(leaseToken: String)

  /** Sign the exact native outstanding request bound to both capabilities. */
  fun signDirectRestRequest(
    leaseToken: String,
    requestToken: String,
  ): NativeRestSignature

  fun disconnect()
}

internal fun interface NativeMobileSessionFactory {
  fun create(mnemonicUtf8: ByteArray, databasePath: String): NativeMobileSession
}

internal class VeilMobileRuntime internal constructor(
  private val vault: NativeIdentityVaultAccess,
  private val passStore: NodeAccessPassStore,
  private val sessionFactory: NativeMobileSessionFactory,
  private val cancellationFactory: NativeConnectCancellationFactory,
  private val directTransport: NativeDirectHttpExecutor,
  private val executor: ExecutorService,
  private val databasePathProvider: () -> String,
) {
  constructor(context: Context) : this(
    vault = NativeIdentityVault(context.applicationContext),
    passStore = NodeAccessPassStore(clockMillis = { SystemClock.elapsedRealtime() }),
    sessionFactory = UniFfiMobileSessionFactory,
    cancellationFactory = UniFfiConnectCancellationFactory,
    directTransport = NativeDirectHttpTransport(),
    executor = newRuntimeExecutor(),
    databasePathProvider = { resolveDatabasePath(context.applicationContext) },
  )

  private val listeners = CopyOnWriteArraySet<(VeilMobileRuntimeSnapshot) -> Unit>()
  private val stateLock = Any()
  private val publicationLock = Any()
  private var publicationInProgress = false
  private var publicationPending = false

  private var session: NativeMobileSession? = null
  private var sessionState = NativeSessionState.LOCKED
  private var connectionState = NativeConnectionState.DISCONNECTED
  private var binding: PublicAuthenticatedBinding? = null
  private var directoryReady = false
  private var ownPreKeyState = NativeOwnPreKeyState.IDLE
  private var directDirectoryState = NativeDirectDirectoryState.IDLE
  private var directConversations: List<NativeDirectConversationInstall> = emptyList()
  // Process-scoped runtimes start without UI authority. Only an Activity
  // lifecycle transition may grant foreground access; this prevents a cold
  // headless process (for example future push handling) from opening the
  // encrypted account before any visible Veil surface exists.
  private var foreground = false
  private var lifecycleEpoch = 0L
  private var activeConnect: ActiveConnect? = null
  private var activeDirectSync: ActiveDirectSync? = null

  private data class ActiveConnect(
    val session: NativeMobileSession,
    val cancellation: NativeConnectCancellation,
    val epoch: Long,
  )

  private data class ConnectStart(
    val attempt: ActiveConnect,
    val detachedDirectSync: DetachedDirectSync?,
  )

  private data class BackgroundLockRequest(
    val epoch: Long,
    val detachedDirectSync: DetachedDirectSync?,
  )

  private class ActiveDirectSync(
    val session: NativeMobileSession,
    val epoch: Long,
    val leaseToken: String,
    val canonicalServerOrigin: String,
    val userId: String,
  ) {
    val conversations = LinkedHashMap<String, NativeDirectConversationInstall>()
    var pendingRequest: PendingDirectRequest? = null
    var ownPreKeyRequestsPrepared = 0

    override fun toString(): String =
      "ActiveDirectSync(epoch=$epoch, canonicalServerOrigin=$canonicalServerOrigin, " +
        "userId=$userId, leaseToken=[REDACTED], conversations=${conversations.size})"
  }

  private class PendingDirectRequest(
    val requestToken: String,
    val stage: DirectRequestStage,
    val method: NativeDirectHttpMethod,
  ) {
    var call: NativeDirectHttpCall? = null

    override fun toString(): String =
      "PendingDirectRequest(" +
        "stage=$stage, method=$method, requestToken=[REDACTED], " +
        "callAttached=${call != null})"
  }

  private enum class DirectRequestStage {
    OWN_PREKEY,
    DIRECTORY,
  }

  private class PreparedDirectHttpRequest(
    val pending: PendingDirectRequest,
    val httpRequest: NativeDirectHttpRequest,
    private val wireBody: ByteArray,
  ) {
    fun wipeWireBody() {
      wireBody.fill(0)
    }

    override fun toString(): String =
      "PreparedDirectHttpRequest(pending=$pending, httpRequest=$httpRequest, wireBody=[REDACTED])"
  }

  private data class DetachedDirectSync(
    val session: NativeMobileSession,
    val leaseToken: String,
    val pendingCall: NativeDirectHttpCall?,
  ) {
    override fun toString(): String =
      "DetachedDirectSync(leaseToken=[REDACTED], pendingCall=${pendingCall != null})"
  }

  fun execute(operation: () -> Unit) {
    executor.execute(operation)
  }

  fun addListener(listener: (VeilMobileRuntimeSnapshot) -> Unit) {
    listeners.add(listener)
  }

  fun removeListener(listener: (VeilMobileRuntimeSnapshot) -> Unit) {
    listeners.remove(listener)
  }

  fun consumeEnrollmentUri(raw: String): Boolean {
    if (!NodeAccessPassParser.isPotentialEnrollment(raw)) return false
    try {
      passStore.stage(raw)
    } catch (_: Throwable) {
      // Enrollment errors are deliberately generic. Never attach the raw URI
      // or parser input to logs, crash metadata, or a React Native event.
    }
    publishSnapshot()
    return true
  }

  fun snapshot(): VeilMobileRuntimeSnapshot = synchronized(stateLock) {
    snapshotLocked()
  }

  fun openSession(): VeilMobileRuntimeSnapshot {
    val openingEpoch = synchronized(stateLock) {
      if (!foreground) {
        throw VeilMobileRuntimeException("E_VEIL_LOCKED", "Return to Veil before opening the local account")
      }
      if (session != null) {
        if (sessionState == NativeSessionState.CLOSING) {
          throw VeilMobileRuntimeException("E_VEIL_LOCKED", "The local account is still locking")
        }
        sessionState = NativeSessionState.OPEN
        return snapshotLocked()
      }
      lifecycleEpoch += 1
      sessionState = NativeSessionState.OPENING
      connectionState = NativeConnectionState.DISCONNECTED
      binding = null
      directoryReady = false
      ownPreKeyState = NativeOwnPreKeyState.IDLE
      directDirectoryState = NativeDirectDirectoryState.IDLE
      directConversations = emptyList()
      lifecycleEpoch
    }
    publishSnapshot()

    val candidate = try {
      vault.withMnemonicBytes { mnemonicUtf8 ->
        sessionFactory.create(mnemonicUtf8, databasePathProvider())
      }
    } catch (_: Throwable) {
      synchronized(stateLock) {
        if (foreground && lifecycleEpoch == openingEpoch && session == null) {
          sessionState = NativeSessionState.ERROR
          connectionState = NativeConnectionState.DISCONNECTED
          binding = null
          directoryReady = false
          ownPreKeyState = NativeOwnPreKeyState.IDLE
          directDirectoryState = NativeDirectDirectoryState.IDLE
          directConversations = emptyList()
        }
      }
      publishSnapshot()
      throw VeilMobileRuntimeException("E_VEIL_OPEN", "Unable to open the encrypted local account")
    }

    val installed = synchronized(stateLock) {
      if (
        foreground &&
        lifecycleEpoch == openingEpoch &&
        session == null &&
        sessionState == NativeSessionState.OPENING
      ) {
        session = candidate
        sessionState = NativeSessionState.OPEN
        connectionState = NativeConnectionState.DISCONNECTED
        true
      } else {
        false
      }
    }
    if (!installed) {
      candidate.closeQuietly()
      publishSnapshot()
      throw VeilMobileRuntimeException("E_VEIL_LOCKED", "The local account was locked while opening")
    }
    return publishSnapshot()
  }

  fun connect(rawOrigin: String): PublicAuthenticatedBinding {
    val origin = try {
      CanonicalServerOrigin.parse(rawOrigin)
    } catch (_: Throwable) {
      throw VeilMobileRuntimeException("E_VEIL_ENDPOINT", "The Veil Node origin is invalid")
    }
    return connectInternal(origin, null)
  }

  fun connectPendingAccessPass(expectedFlowId: String): PublicAuthenticatedBinding {
    val view = try {
      passStore.snapshot()
    } catch (_: Throwable) {
      null
    } ?: throw VeilMobileRuntimeException(
      "E_VEIL_ACCESS_PASS",
      "The pending Node Access Pass is unavailable or expired",
    )
    if (view.flowId != expectedFlowId) {
      throw VeilMobileRuntimeException("E_VEIL_ACCESS_PASS", "The pending Node Access Pass changed")
    }
    val origin = try {
      CanonicalServerOrigin.parse(view.canonicalOrigin, allowLoopbackHttp = false)
    } catch (_: Throwable) {
      throw VeilMobileRuntimeException("E_VEIL_ACCESS_PASS", "The pending Node Access Pass origin is invalid")
    }
    val attempt = try {
      passStore.attempt(expectedFlowId, origin.value)
    } catch (_: Throwable) {
      null
    } ?: throw VeilMobileRuntimeException(
      "E_VEIL_ACCESS_PASS",
      "The pending Node Access Pass is unavailable or expired",
    )
    attempt.use {
      return connectInternal(origin, attempt)
    }
  }

  private fun connectInternal(
    origin: CanonicalServerOrigin,
    accessAttempt: NodeAccessPassAttempt?,
  ): PublicAuthenticatedBinding {
    val start = synchronized(stateLock) {
      if (!foreground) {
        throw VeilMobileRuntimeException("E_VEIL_LOCKED", "Return to Veil before connecting")
      }
      val active = session
        ?: throw VeilMobileRuntimeException("E_VEIL_LOCKED", "Open the local account before connecting")
      if (sessionState != NativeSessionState.OPEN) {
        throw VeilMobileRuntimeException("E_VEIL_LOCKED", "The local account is not ready to connect")
      }
      if (activeConnect != null) {
        throw VeilMobileRuntimeException("E_VEIL_CONNECTING", "A connection attempt is already running")
      }
      val pending = ActiveConnect(
        session = active,
        cancellation = cancellationFactory.create(),
        epoch = lifecycleEpoch,
      )
      val detachedDirectSync = detachDirectSyncLocked(NativeDirectDirectoryState.IDLE)
      activeConnect = pending
      connectionState = NativeConnectionState.CONNECTING
      binding = null
      ConnectStart(pending, detachedDirectSync)
    }
    val attempt = start.attempt
    val active = attempt.session
    start.detachedDirectSync.cancelHttpQuietly()
    start.detachedDirectSync.cancelLeaseQuietly()
    publishSnapshot()

    try {
      active.disconnect()
    } catch (_: Throwable) {
      // A stale transport must not prevent a fresh, serialized connection.
    }

    return try {
      val mayConnect = synchronized(stateLock) {
        foreground &&
          lifecycleEpoch == attempt.epoch &&
          session === active &&
          activeConnect === attempt
      }
      if (!mayConnect) {
        throw VeilMobileRuntimeException("E_VEIL_CANCELLED", "Connection attempt was cancelled")
      }

      val authenticated = if (accessAttempt == null) {
        active.connect(origin.websocketUrl, origin.value, attempt.cancellation)
      } else {
        active.connectWithNodeAccessPass(
          origin.websocketUrl,
          origin.value,
          accessAttempt.token,
          attempt.cancellation,
        )
      }
      requireAuthenticatedBinding(authenticated, origin)

      val accepted = synchronized(stateLock) {
        val current = foreground &&
          lifecycleEpoch == attempt.epoch &&
          session === active &&
          activeConnect === attempt
        if (activeConnect === attempt) activeConnect = null
        if (current) {
          binding = authenticated
          connectionState = NativeConnectionState.CONNECTED
        }
        current
      }
      if (!accepted) {
        throw VeilMobileRuntimeException("E_VEIL_CANCELLED", "Connection attempt was cancelled")
      }
      if (accessAttempt != null) passStore.clearAfterSuccess(accessAttempt.flowId)
      startDirectSyncBootstrap(active, attempt.epoch, authenticated)
      publishSnapshot()
      authenticated
    } catch (error: Throwable) {
      val failedSync = synchronized(stateLock) {
        val connecting = activeConnect === attempt
        if (connecting) activeConnect = null
        val authenticated = binding
        val current = foreground &&
          lifecycleEpoch == attempt.epoch &&
          session === active &&
          (connecting || authenticated != null)
        if (
          current
        ) {
          val detached = detachDirectSyncLocked(NativeDirectDirectoryState.ERROR)
          connectionState = NativeConnectionState.ERROR
          binding = null
          detached
        } else {
          null
        }
      }
      failedSync.cancelHttpQuietly()
      failedSync.cancelLeaseQuietly()
      try {
        active.disconnect()
      } catch (_: Throwable) {
        // Preserve the original, sanitized connection failure.
      }
      publishSnapshot()
      if (error is VeilMobileRuntimeException) throw error
      throw publicConnectError(error)
    } finally {
      try {
        attempt.cancellation.close()
      } catch (_: Throwable) {
        // The one-shot token contains no session state; its native cleaner is
        // still a fallback if explicit release reports an unexpected error.
      }
    }
  }

  private fun requireAuthenticatedBinding(
    authenticated: PublicAuthenticatedBinding,
    expectedOrigin: CanonicalServerOrigin,
  ) {
    val canonicalUserId = try {
      UUID.fromString(authenticated.userId).toString()
    } catch (_: IllegalArgumentException) {
      null
    }
    if (
      authenticated.canonicalServerOrigin != expectedOrigin.value ||
      canonicalUserId != authenticated.userId
    ) {
      throw VeilMobileRuntimeException(
        "E_VEIL_CONNECT",
        "Unable to authenticate with the Veil Node",
      )
    }
  }

  private fun startDirectSyncBootstrap(
    active: NativeMobileSession,
    epoch: Long,
    authenticated: PublicAuthenticatedBinding,
  ) {
    val lease = try {
      active.beginDirectSync()
    } catch (_: Throwable) {
      throw VeilMobileRuntimeException("E_VEIL_SYNC", SECURE_DIRECT_BOOTSTRAP_ERROR)
    }
    if (
      lease.canonicalServerOrigin != authenticated.canonicalServerOrigin ||
      lease.userId != authenticated.userId
    ) {
      DetachedDirectSync(active, lease.leaseToken, null).cancelLeaseQuietly()
      throw VeilMobileRuntimeException("E_VEIL_SYNC", SECURE_DIRECT_BOOTSTRAP_ERROR)
    }

    val sync = ActiveDirectSync(
      session = active,
      epoch = epoch,
      leaseToken = lease.leaseToken,
      canonicalServerOrigin = lease.canonicalServerOrigin,
      userId = lease.userId,
    )
    val installed = synchronized(stateLock) {
      if (
        foreground &&
        lifecycleEpoch == epoch &&
        session === active &&
        sessionState == NativeSessionState.OPEN &&
        connectionState == NativeConnectionState.CONNECTED &&
        binding == authenticated &&
        activeDirectSync == null
      ) {
        activeDirectSync = sync
        ownPreKeyState = NativeOwnPreKeyState.CHECKING
        directDirectoryState = NativeDirectDirectoryState.IDLE
        directConversations = emptyList()
        directoryReady = false
        true
      } else {
        false
      }
    }
    if (!installed) {
      DetachedDirectSync(active, lease.leaseToken, null).cancelLeaseQuietly()
      throw VeilMobileRuntimeException("E_VEIL_CANCELLED", "Connection attempt was cancelled")
    }

    try {
      requestNextOwnPreKeyStep(sync)
    } catch (_: Throwable) {
      failDirectSync(sync)
      throw VeilMobileRuntimeException("E_VEIL_SYNC", SECURE_DIRECT_BOOTSTRAP_ERROR)
    }
  }

  /**
   * Run the native-owned count/outbox protocol before any directory request.
   * Native chooses every method, target, body, id, and retry. Android only
   * signs and transports the exact prepared DTO under this generation.
   */
  private fun requestNextOwnPreKeyStep(sync: ActiveDirectSync) {
    val mayPrepare = synchronized(stateLock) {
      val current = isCurrentDirectSyncLocked(sync) &&
        sync.pendingRequest == null &&
        ownPreKeyState != NativeOwnPreKeyState.PUBLISHED
      if (current) {
        check(sync.ownPreKeyRequestsPrepared < MAX_OWN_PREKEY_REQUESTS) {
          "native own-prekey bootstrap exceeded its request bound"
        }
      }
      current
    }
    if (!mayPrepare) return

    val prepared = sync.session.prepareOwnPreKeyRequest(sync.leaseToken)
    val signed = prepareSignedDirectRequest(sync, prepared, DirectRequestStage.OWN_PREKEY)
    val pending = signed.pending
    val call = try {
      directTransport.createCall(signed.httpRequest) { result ->
        enqueueOwnPreKeyResult(sync, pending, result)
      }
    } finally {
      // NativeDirectHttpExecutor synchronously snapshots request bytes while
      // creating an unstarted call. Wipe Android's transport copy before the
      // call can be attached to the active lease or started.
      signed.wipeWireBody()
    }

    val registered = try {
      synchronized(stateLock) {
        if (
          isCurrentDirectSyncLocked(sync) &&
          sync.pendingRequest == null &&
          ownPreKeyState != NativeOwnPreKeyState.PUBLISHED
        ) {
          if (sync.ownPreKeyRequestsPrepared == 1) {
            check(pending.method == NativeDirectHttpMethod.POST) {
              "native own-prekey upload did not follow the count request"
            }
          }
          sync.pendingRequest = pending
          sync.ownPreKeyRequestsPrepared += 1
          ownPreKeyState = when (pending.method) {
            NativeDirectHttpMethod.GET -> NativeOwnPreKeyState.CHECKING
            NativeDirectHttpMethod.POST -> NativeOwnPreKeyState.PUBLISHING
          }
          pending.call = call
          true
        } else {
          false
        }
      }
    } catch (error: Throwable) {
      call.cancelQuietly()
      throw error
    }
    if (!registered) {
      call.cancelQuietly()
      return
    }
    // Lifecycle/reconnect teardown may cancel between attachment and this
    // call. NativeDirectHttpCall.start is fail-closed after such cancellation,
    // so a revoked lease can never launch the prepared request.
    call.start()
  }

  private fun enqueueOwnPreKeyResult(
    sync: ActiveDirectSync,
    pending: PendingDirectRequest,
    result: NativeDirectHttpResult,
  ) {
    try {
      executor.execute {
        handleOwnPreKeyResult(sync, pending, result)
      }
    } catch (_: RuntimeException) {
      result.wipeSensitiveBody()
    }
  }

  private fun handleOwnPreKeyResult(
    sync: ActiveDirectSync,
    pending: PendingDirectRequest,
    result: NativeDirectHttpResult,
  ) {
    try {
      val current = synchronized(stateLock) {
        isCurrentDirectSyncLocked(sync) &&
          sync.pendingRequest === pending &&
          pending.stage == DirectRequestStage.OWN_PREKEY
      }
      if (!current) return
      if (result !is NativeDirectHttpResult.Success) {
        failDirectSync(sync)
        return
      }

      val progress = sync.session.installOwnPreKeyResponse(
        sync.leaseToken,
        pending.requestToken,
        result.body,
      )
      check(
        (pending.method == NativeDirectHttpMethod.GET && !progress.publicationComplete) ||
          (pending.method == NativeDirectHttpMethod.POST && progress.publicationComplete),
      ) { "native own-prekey progress contradicted the prepared request" }

      val accepted = synchronized(stateLock) {
        if (!isCurrentDirectSyncLocked(sync) || sync.pendingRequest !== pending) {
          false
        } else {
          sync.pendingRequest = null
          if (progress.publicationComplete) {
            ownPreKeyState = NativeOwnPreKeyState.PUBLISHED
            directDirectoryState = NativeDirectDirectoryState.SYNCING
          }
          true
        }
      }
      if (!accepted) return

      if (progress.publicationComplete) {
        requestNextDirectDirectoryPage(sync)
      } else {
        requestNextOwnPreKeyStep(sync)
      }
      publishSnapshot()
    } catch (_: Throwable) {
      failDirectSync(sync)
    } finally {
      result.wipeSensitiveBody()
    }
  }

  private fun requestNextDirectDirectoryPage(sync: ActiveDirectSync) {
    val mayPrepare = synchronized(stateLock) {
      isCurrentDirectSyncLocked(sync) &&
        sync.pendingRequest == null &&
        ownPreKeyState == NativeOwnPreKeyState.PUBLISHED
    }
    if (!mayPrepare) return

    val prepared = sync.session.prepareDirectDirectoryRequest(sync.leaseToken)
    val signed = prepareSignedDirectRequest(sync, prepared, DirectRequestStage.DIRECTORY)
    val pending = signed.pending
    val call = try {
      directTransport.createCall(signed.httpRequest) { result ->
        enqueueDirectDirectoryResult(sync, pending, result)
      }
    } finally {
      signed.wipeWireBody()
    }

    val registered = synchronized(stateLock) {
      if (
        isCurrentDirectSyncLocked(sync) &&
        sync.pendingRequest == null &&
        ownPreKeyState == NativeOwnPreKeyState.PUBLISHED
      ) {
        sync.pendingRequest = pending
        pending.call = call
        true
      } else {
        false
      }
    }
    if (!registered) {
      call.cancelQuietly()
      return
    }
    call.start()
  }

  /** Prepare and sign one exact native DTO, rejecting stage/method drift. */
  private fun prepareSignedDirectRequest(
    sync: ActiveDirectSync,
    prepared: NativeDirectRestRequest,
    stage: DirectRequestStage,
  ): PreparedDirectHttpRequest {
    val method = when (prepared.method) {
      HTTP_GET_METHOD -> NativeDirectHttpMethod.GET
      HTTP_POST_METHOD -> NativeDirectHttpMethod.POST
      else -> throw IllegalStateException("native Direct request method is unsupported")
    }
    val exactBody = prepared.body.copyOf()
    prepared.body.fill(0)
    try {
      when (stage) {
        DirectRequestStage.OWN_PREKEY -> when (method) {
          NativeDirectHttpMethod.GET -> {
            check(exactBody.isEmpty()) { "native own-prekey count body is not empty" }
            check(prepared.responseLimitBytes == NativeDirectHttpLimits.OWN_PREKEY_COUNT_BYTES) {
              "native own-prekey count response bound changed"
            }
          }
          NativeDirectHttpMethod.POST -> {
            check(prepared.requestTarget == OWN_PREKEY_UPLOAD_TARGET) {
              "native own-prekey upload target changed"
            }
            check(exactBody.isNotEmpty()) { "native own-prekey upload body is empty" }
            check(prepared.responseLimitBytes == NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES) {
              "native own-prekey upload response bound changed"
            }
          }
        }
        DirectRequestStage.DIRECTORY -> {
          check(method == NativeDirectHttpMethod.GET) { "native Direct directory method changed" }
          check(exactBody.isEmpty()) { "native Direct directory body is not empty" }
          check(prepared.responseLimitBytes == NativeDirectHttpLimits.DIRECTORY_BYTES) {
            "native Direct directory response bound changed"
          }
        }
      }

      val signature = sync.session.signDirectRestRequest(sync.leaseToken, prepared.requestToken)
      check(signature.userId == sync.userId) { "native Direct signer returned a mismatched account" }
      val pending = PendingDirectRequest(
        requestToken = prepared.requestToken,
        stage = stage,
        method = method,
      )
      return PreparedDirectHttpRequest(
        pending = pending,
        httpRequest = NativeDirectHttpRequest(
          canonicalServerOrigin = sync.canonicalServerOrigin,
          requestTarget = prepared.requestTarget,
          signature = signature,
          responseLimitBytes = prepared.responseLimitBytes,
          method = method,
          body = exactBody,
        ),
        wireBody = exactBody,
      )
    } catch (error: Throwable) {
      exactBody.fill(0)
      throw error
    }
  }

  private fun enqueueDirectDirectoryResult(
    sync: ActiveDirectSync,
    pending: PendingDirectRequest,
    result: NativeDirectHttpResult,
  ) {
    try {
      executor.execute {
        handleDirectDirectoryResult(sync, pending, result)
      }
    } catch (_: RuntimeException) {
      result.wipeSensitiveBody()
    }
  }

  private fun handleDirectDirectoryResult(
    sync: ActiveDirectSync,
    pending: PendingDirectRequest,
    result: NativeDirectHttpResult,
  ) {
    try {
      val current = synchronized(stateLock) {
        isCurrentDirectSyncLocked(sync) &&
          sync.pendingRequest === pending &&
          pending.stage == DirectRequestStage.DIRECTORY
      }
      if (!current) return
      if (result !is NativeDirectHttpResult.Success) {
        failDirectSync(sync)
        return
      }

      val installed = sync.session.installDirectDirectoryPage(
        sync.leaseToken,
        pending.requestToken,
        result.body,
      )
      var complete = false
      val accepted = synchronized(stateLock) {
        if (!isCurrentDirectSyncLocked(sync) || sync.pendingRequest !== pending) {
          false
        } else {
          sync.pendingRequest = null
          installed.conversations.forEach { conversation ->
            check(sync.conversations.size < MAX_DIRECT_CONVERSATIONS) {
              "native Direct directory exceeded the mobile publication bound"
            }
            check(sync.conversations.putIfAbsent(conversation.conversationId, conversation) == null) {
              "native Direct directory returned a duplicate conversation"
            }
          }
          if (installed.directoryComplete) {
            directConversations = sync.conversations.values.toList()
            directDirectoryState = NativeDirectDirectoryState.SYNCHRONIZED
            // History is not yet synchronized. Never open the chat surface on
            // a directory-only checkpoint, even when the directory is empty.
            directoryReady = false
            complete = true
          }
          true
        }
      }
      if (!accepted) return
      if (complete) {
        publishSnapshot()
      } else {
        requestNextDirectDirectoryPage(sync)
      }
    } catch (_: Throwable) {
      result.wipeSensitiveBody()
      failDirectSync(sync)
    } finally {
      result.wipeSensitiveBody()
    }
  }

  private fun failDirectSync(sync: ActiveDirectSync) {
    val detached = synchronized(stateLock) {
      if (activeDirectSync !== sync) return
      val selected = detachDirectSyncLocked(NativeDirectDirectoryState.ERROR)
      ownPreKeyState = NativeOwnPreKeyState.ERROR
      if (
        foreground &&
        lifecycleEpoch == sync.epoch &&
        session === sync.session
      ) {
        connectionState = NativeConnectionState.ERROR
        binding = null
      }
      selected
    }
    detached.cancelHttpQuietly()
    detached.cancelLeaseQuietly()
    try {
      sync.session.disconnect()
    } catch (_: Throwable) {
      // The public state is already fail-closed; transport teardown is best effort.
    }
    publishSnapshot()
  }

  private fun isCurrentDirectSyncLocked(sync: ActiveDirectSync): Boolean {
    val currentBinding = binding
    return activeDirectSync === sync &&
      foreground &&
      lifecycleEpoch == sync.epoch &&
      session === sync.session &&
      sessionState == NativeSessionState.OPEN &&
      connectionState == NativeConnectionState.CONNECTED &&
      currentBinding != null &&
      currentBinding.canonicalServerOrigin == sync.canonicalServerOrigin &&
      currentBinding.userId == sync.userId
  }

  private fun detachDirectSyncLocked(
    nextState: NativeDirectDirectoryState,
  ): DetachedDirectSync? {
    val selected = activeDirectSync
    activeDirectSync = null
    val pendingCall = selected?.pendingRequest?.call
    // Cancel under the same lock that revokes the generation. This closes the
    // tiny attach-before-start window: once lifecycle/reconnect has linearized
    // here, a still-unstarted call is terminal before the requester can start
    // it. The out-of-lock cancellation below remains an idempotent fallback.
    pendingCall?.cancelQuietly()
    selected?.pendingRequest = null
    ownPreKeyState = if (nextState == NativeDirectDirectoryState.ERROR) {
      NativeOwnPreKeyState.ERROR
    } else {
      NativeOwnPreKeyState.IDLE
    }
    directDirectoryState = nextState
    directConversations = emptyList()
    directoryReady = false
    return selected?.let { sync ->
      DetachedDirectSync(sync.session, sync.leaseToken, pendingCall)
    }
  }

  private fun DetachedDirectSync?.cancelHttpQuietly() {
    val selected = this ?: return
    try {
      selected.pendingCall?.cancel()
    } catch (_: Throwable) {
      // Detaching remains terminal even if the HTTP call already completed.
    }
  }

  private fun DetachedDirectSync?.cancelLeaseQuietly() {
    val selected = this ?: return
    try {
      selected.session.cancelDirectSync(selected.leaseToken)
    } catch (_: Throwable) {
      // Native generation checks still reject stale request capabilities.
    }
  }

  private fun NativeDirectHttpCall.cancelQuietly() {
    try {
      cancel()
    } catch (_: Throwable) {
      // The detached generation can no longer publish through the runtime.
    }
  }

  fun disconnect(): VeilMobileRuntimeSnapshot {
    val target = synchronized(stateLock) {
      Triple(
        session,
        lifecycleEpoch,
        detachDirectSyncLocked(NativeDirectDirectoryState.IDLE),
      )
    }
    val active = target.first
    target.third.cancelHttpQuietly()
    target.third.cancelLeaseQuietly()
    try {
      active?.disconnect()
    } catch (_: Throwable) {
      synchronized(stateLock) {
        if (
          foreground &&
          lifecycleEpoch == target.second &&
          session === active
        ) {
          connectionState = NativeConnectionState.ERROR
          binding = null
          directoryReady = false
        }
      }
      publishSnapshot()
      throw VeilMobileRuntimeException("E_VEIL_DISCONNECT", "Unable to close the Veil Node connection cleanly")
    }
    synchronized(stateLock) {
      if (lifecycleEpoch == target.second && session === active) {
        connectionState = NativeConnectionState.DISCONNECTED
        binding = null
      }
    }
    return publishSnapshot()
  }

  fun lockSession(): VeilMobileRuntimeSnapshot {
    val target = synchronized(stateLock) {
      lifecycleEpoch += 1
      // Cancel while holding the same lock that owns activeConnect. The
      // connect finalizer cannot clear the attempt and close its UniFFI handle
      // between selecting it and this call. Rust cancellation is deliberately
      // atomic/non-blocking and never calls back into this runtime.
      activeConnect?.cancellation?.cancelQuietly()
      activeConnect = null
      sessionState = NativeSessionState.CLOSING
      connectionState = NativeConnectionState.DISCONNECTED
      binding = null
      val detachedDirectSync = detachDirectSyncLocked(NativeDirectDirectoryState.IDLE)
      Pair(session.also { session = null }, detachedDirectSync)
    }
    val active = target.first
    target.second.cancelHttpQuietly()
    publishSnapshot()
    try {
      target.second.cancelLeaseQuietly()
      active?.disconnect()
    } catch (_: Throwable) {
      // Lock remains fail-closed even if transport teardown reports an error.
    } finally {
      active?.closeQuietly()
      passStore.close()
    }
    synchronized(stateLock) {
      sessionState = NativeSessionState.LOCKED
    }
    return publishSnapshot()
  }

  fun markForeground(): VeilMobileRuntimeSnapshot {
    synchronized(stateLock) {
      if (foreground) return snapshotLocked()
      foreground = true
    }
    return publishSnapshot()
  }

  fun lockForBackground() {
    val request = synchronized(stateLock) {
      foreground = false
      lifecycleEpoch += 1
      // See lockSession(): selecting and cancelling the capability must be one
      // linearized state transition so onStop cannot race a UniFFI close.
      activeConnect?.cancellation?.cancelQuietly()
      sessionState = NativeSessionState.CLOSING
      connectionState = NativeConnectionState.DISCONNECTED
      binding = null
      val detachedDirectSync = detachDirectSyncLocked(NativeDirectDirectoryState.IDLE)
      BackgroundLockRequest(lifecycleEpoch, detachedDirectSync)
    }
    request.detachedDirectSync.cancelHttpQuietly()
    passStore.close()
    publishSnapshot()
    execute {
      finalizeBackgroundLock(request)
    }
  }

  private fun finalizeBackgroundLock(request: BackgroundLockRequest) {
    // A superseding lifecycle epoch may own final session teardown, but it
    // cannot inherit this detached Direct capability. Revoke the lease first.
    request.detachedDirectSync.cancelLeaseQuietly()
    val active = synchronized(stateLock) {
      if (lifecycleEpoch != request.epoch) return
      activeConnect = null
      session.also { session = null }
    }
    try {
      active?.disconnect()
    } catch (_: Throwable) {
      // Background teardown remains fail-closed even after transport errors.
    } finally {
      active?.closeQuietly()
    }
    synchronized(stateLock) {
      if (lifecycleEpoch == request.epoch && session == null) {
        sessionState = NativeSessionState.LOCKED
        connectionState = NativeConnectionState.DISCONNECTED
        binding = null
      }
    }
    publishSnapshot()
  }

  fun cancelPendingAccessPass(expectedFlowId: String): Boolean {
    val cancelled = try {
      passStore.cancel(expectedFlowId)
    } catch (_: Throwable) {
      throw VeilMobileRuntimeException("E_VEIL_ACCESS_PASS", "The pending Node Access Pass reference is invalid")
    }
    publishSnapshot()
    return cancelled
  }

  private fun publishSnapshot(): VeilMobileRuntimeSnapshot {
    val ownsPublication = synchronized(publicationLock) {
      publicationPending = true
      if (publicationInProgress) {
        false
      } else {
        publicationInProgress = true
        true
      }
    }
    if (!ownsPublication) return snapshot()

    lateinit var lastPublished: VeilMobileRuntimeSnapshot
    try {
      while (true) {
        synchronized(publicationLock) {
          publicationPending = false
        }
        lastPublished = snapshot()
        listeners.forEach { listener ->
          try {
            listener(lastPublished)
          } catch (_: Throwable) {
            // One detached React context must not break native state publication.
          }
        }
        val complete = synchronized(publicationLock) {
          if (publicationPending) {
            false
          } else {
            publicationInProgress = false
            true
          }
        }
        if (complete) return lastPublished
      }
    } catch (error: Throwable) {
      synchronized(publicationLock) {
        publicationInProgress = false
        publicationPending = false
      }
      throw error
    }
  }

  private fun snapshotLocked(): VeilMobileRuntimeSnapshot {
    val identityExists = session != null || try {
      vault.hasIdentity()
    } catch (_: Throwable) {
      false
    }
    return VeilMobileRuntimeSnapshot(
      identityExists = identityExists,
      sessionState = sessionState,
      connectionState = connectionState,
      directoryReady = directoryReady,
      secureSyncState = secureSyncStateLocked(),
      ownPreKeyState = ownPreKeyState,
      directDirectoryState = directDirectoryState,
      directConversations = directConversations.toList(),
      binding = binding,
      pendingAccessPass = try {
        passStore.snapshot()
      } catch (_: Throwable) {
        null
      },
    )
  }

  private fun secureSyncStateLocked(): NativeSecureSyncState = when {
    connectionState == NativeConnectionState.ERROR ||
      ownPreKeyState == NativeOwnPreKeyState.ERROR ||
      directDirectoryState == NativeDirectDirectoryState.ERROR -> NativeSecureSyncState.ERROR
    ownPreKeyState == NativeOwnPreKeyState.CHECKING ||
      ownPreKeyState == NativeOwnPreKeyState.PUBLISHING -> NativeSecureSyncState.PUBLISHING_KEYS
    directDirectoryState == NativeDirectDirectoryState.SYNCING -> NativeSecureSyncState.SYNCING_DIRECTORY
    directDirectoryState == NativeDirectDirectoryState.SYNCHRONIZED ->
      NativeSecureSyncState.DIRECTORY_SYNCHRONIZED
    else -> NativeSecureSyncState.IDLE
  }

  private fun publicConnectError(error: Throwable): VeilMobileRuntimeException {
    val detail = error.message.orEmpty().lowercase()
    return when {
      "mobile connection attempt cancelled" in detail -> VeilMobileRuntimeException(
        "E_VEIL_CANCELLED",
        "Connection attempt was cancelled",
      )
      "registration is closed" in detail -> VeilMobileRuntimeException(
        "E_VEIL_ACCESS_REQUIRED",
        "Registration on this Veil Node requires a valid Node Access Pass",
      )
      "access pass is invalid" in detail || "invite" in detail && "invalid" in detail ->
        VeilMobileRuntimeException(
          "E_VEIL_ACCESS_PASS",
          "The Node Access Pass is invalid, expired, or already used",
        )
      else -> VeilMobileRuntimeException("E_VEIL_CONNECT", "Unable to authenticate with the Veil Node")
    }
  }

  companion object {
    private const val HTTP_GET_METHOD = "GET"
    private const val HTTP_POST_METHOD = "POST"
    private const val OWN_PREKEY_UPLOAD_TARGET = "/v1/prekeys"
    private const val MAX_OWN_PREKEY_REQUESTS = 2
    private const val SECURE_DIRECT_BOOTSTRAP_ERROR = "Unable to complete the secure Direct bootstrap"
    private const val MAX_DIRECT_CONVERSATIONS = 10_000

    private fun newRuntimeExecutor(): ExecutorService =
      Executors.newSingleThreadExecutor { operation ->
        Thread(operation, "veil-mobile-runtime").apply { isDaemon = true }
      }

    private fun resolveDatabasePath(context: Context): String {
      val root = File(context.noBackupFilesDir, "veil/sqlcipher").canonicalFile
      if (!root.isDirectory && !root.mkdirs()) {
        throw IllegalStateException("unable to create the encrypted database directory")
      }
      val database = File(root, "account-v1.db").canonicalFile
      val prefix = root.path + File.separator
      check(database.path.startsWith(prefix)) { "encrypted database path escaped its private root" }
      return database.absolutePath
    }
  }
}

private object UniFfiMobileSessionFactory : NativeMobileSessionFactory {
  override fun create(mnemonicUtf8: ByteArray, databasePath: String): NativeMobileSession =
    UniFfiMobileSession(VeilMobileSession.fromMnemonicBytes(mnemonicUtf8, databasePath))
}

private object UniFfiConnectCancellationFactory : NativeConnectCancellationFactory {
  override fun create(): NativeConnectCancellation =
    UniFfiConnectCancellation(MobileConnectCancellation())
}

private class UniFfiConnectCancellation(
  val delegate: MobileConnectCancellation,
) : NativeConnectCancellation {
  override fun cancel() {
    delegate.cancel()
  }

  override fun close() {
    delegate.close()
  }
}

private class UniFfiMobileSession(
  private val delegate: VeilMobileSession,
) : NativeMobileSession {
  override fun connect(
    websocketUrl: String,
    canonicalOrigin: String,
    cancellation: NativeConnectCancellation,
  ): PublicAuthenticatedBinding =
    delegate.connectCancellable(
      websocketUrl,
      canonicalOrigin,
      cancellation.requireUniFfiDelegate(),
    ).toPublicBinding()

  override fun connectWithNodeAccessPass(
    websocketUrl: String,
    canonicalOrigin: String,
    nodeAccessPass: ByteArray,
    cancellation: NativeConnectCancellation,
  ): PublicAuthenticatedBinding =
    delegate.connectWithNodeAccessPassCancellable(
      websocketUrl,
      canonicalOrigin,
      nodeAccessPass,
      cancellation.requireUniFfiDelegate(),
    ).toPublicBinding()

  override fun beginDirectSync(): NativeDirectSyncLease =
    delegate.beginDirectSync().toNativeDirectSyncLease()

  override fun prepareOwnPreKeyRequest(leaseToken: String): NativeDirectRestRequest =
    delegate.prepareOwnPrekeyRequest(leaseToken).toNativeDirectRestRequest()

  override fun installOwnPreKeyResponse(
    leaseToken: String,
    requestToken: String,
    response: ByteArray,
  ): NativeDirectOwnPreKeyProgress =
    delegate.installOwnPrekeyResponse(leaseToken, requestToken, response)
      .toNativeDirectOwnPreKeyProgress()

  override fun prepareDirectDirectoryRequest(leaseToken: String): NativeDirectRestRequest =
    delegate.prepareDirectDirectoryRequest(leaseToken).toNativeDirectRestRequest()

  override fun installDirectDirectoryPage(
    leaseToken: String,
    requestToken: String,
    response: ByteArray,
  ): NativeDirectDirectoryInstall =
    delegate.installDirectDirectoryPage(leaseToken, requestToken, response).toNativeDirectDirectoryInstall()

  override fun prepareDirectPreKeyRequest(
    leaseToken: String,
    conversationId: String,
  ): NativeDirectRestRequest =
    delegate.prepareDirectPrekeyRequest(leaseToken, conversationId).toNativeDirectRestRequest()

  override fun installDirectPreKeyBundle(
    leaseToken: String,
    requestToken: String,
    conversationId: String,
    response: ByteArray,
  ): NativeDirectPreKeyInstall =
    delegate.installDirectPrekeyBundle(leaseToken, requestToken, conversationId, response)
      .toNativeDirectPreKeyInstall()

  override fun cancelDirectSync(leaseToken: String) {
    delegate.cancelDirectSync(leaseToken)
  }

  override fun signDirectRestRequest(
    leaseToken: String,
    requestToken: String,
  ): NativeRestSignature =
    delegate.signDirectRestRequest(leaseToken, requestToken).toNativeRestSignature()

  override fun disconnect() {
    delegate.disconnect()
  }

  override fun close() {
    delegate.close()
  }
}

private fun NativeConnectCancellation.requireUniFfiDelegate(): MobileConnectCancellation =
  (this as? UniFfiConnectCancellation)?.delegate
    ?: throw IllegalStateException("native mobile cancellation capability is incompatible")

private fun NativeConnectCancellation.cancelQuietly() {
  try {
    cancel()
  } catch (_: Throwable) {
    // A capability can only be absent here if its connect attempt already
    // completed and cleared activeConnect under stateLock. Keep lifecycle
    // teardown fail-closed and never reflect native diagnostics to Android.
  }
}

private fun MobileAuthenticatedBinding.toPublicBinding(): PublicAuthenticatedBinding =
  PublicAuthenticatedBinding(canonicalServerOrigin = canonicalServerOrigin, userId = userId)

internal fun MobileDirectSyncLease.toNativeDirectSyncLease(): NativeDirectSyncLease =
  NativeDirectSyncLease(
    leaseToken = token,
    canonicalServerOrigin = canonicalServerOrigin,
    userId = userId,
  )

internal fun MobileDirectRestRequest.toNativeDirectRestRequest(): NativeDirectRestRequest {
  val copiedBody = body.copyOf()
  body.fill(0)
  return NativeDirectRestRequest(
    requestToken = requestToken,
    method = method,
    requestTarget = requestTarget,
    body = copiedBody,
    responseLimitBytes = responseLimitBytes.toLong(),
  )
}

internal fun MobileDirectOwnPreKeyProgress.toNativeDirectOwnPreKeyProgress(): NativeDirectOwnPreKeyProgress =
  NativeDirectOwnPreKeyProgress(publicationComplete = publicationComplete)

internal fun MobileDirectConversationData.toNativeDirectConversationInstall(): NativeDirectConversationInstall =
  NativeDirectConversationInstall(
    conversationId = conversationId,
    name = name,
    peerUserId = peerUserId,
    peerUsername = peerUsername,
    needsPreKey = needsPrekey,
  )

internal fun MobileDirectDirectoryPageData.toNativeDirectDirectoryInstall(): NativeDirectDirectoryInstall =
  NativeDirectDirectoryInstall(
    conversations = conversations.map { conversation ->
      conversation.toNativeDirectConversationInstall()
    },
    directoryComplete = directoryComplete,
  )

internal fun MobileDirectPreKeyResult.toNativeDirectPreKeyInstall(): NativeDirectPreKeyInstall =
  NativeDirectPreKeyInstall(
    status = when (status) {
      "established" -> NativeDirectPreKeyInstallStatus.ESTABLISHED
      "already_established" -> NativeDirectPreKeyInstallStatus.ALREADY_ESTABLISHED
      else -> throw IllegalStateException("native Direct prekey install returned an unsupported status")
    },
  )

internal fun RestSignatureData.toNativeRestSignature(): NativeRestSignature =
  NativeRestSignature(
    userId = userId,
    timestampMs = timestampMs,
    signatureBase64 = signatureBase64,
  )

private fun NativeMobileSession.closeQuietly() {
  try {
    close()
  } catch (_: Throwable) {
    // Explicit teardown is best effort; the UniFFI cleaner remains a fallback.
  }
}
