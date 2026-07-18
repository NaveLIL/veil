package io.veil.mobile.runtime

import android.content.Context
import android.os.SystemClock
import io.veil.mobile.crypto.NativeIdentityVault
import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.io.File
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import uniffi.veil_ffi.MobileAuthenticatedBinding
import uniffi.veil_ffi.MobileConnectCancellation
import uniffi.veil_ffi.MobileDirectConversationData
import uniffi.veil_ffi.MobileDirectDirectoryPageData
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
  val requestTarget: String,
) {
  override fun toString(): String =
    "NativeDirectRestRequest(requestTarget=[REDACTED], requestToken=[REDACTED])"
}

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
)

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

  fun signRestRequest(
    canonicalServerOrigin: String,
    method: String,
    requestTarget: String,
    body: ByteArray,
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
  private val executor: ExecutorService,
  private val databasePathProvider: () -> String,
) {
  constructor(context: Context) : this(
    vault = NativeIdentityVault(context.applicationContext),
    passStore = NodeAccessPassStore(clockMillis = { SystemClock.elapsedRealtime() }),
    sessionFactory = UniFfiMobileSessionFactory,
    cancellationFactory = UniFfiConnectCancellationFactory,
    executor = newRuntimeExecutor(),
    databasePathProvider = { resolveDatabasePath(context.applicationContext) },
  )

  private val listeners = CopyOnWriteArraySet<(VeilMobileRuntimeSnapshot) -> Unit>()
  private val stateLock = Any()

  private var session: NativeMobileSession? = null
  private var sessionState = NativeSessionState.LOCKED
  private var connectionState = NativeConnectionState.DISCONNECTED
  private var binding: PublicAuthenticatedBinding? = null
  private var directoryReady = false
  // Process-scoped runtimes start without UI authority. Only an Activity
  // lifecycle transition may grant foreground access; this prevents a cold
  // headless process (for example future push handling) from opening the
  // encrypted account before any visible Veil surface exists.
  private var foreground = false
  private var lifecycleEpoch = 0L
  private var activeConnect: ActiveConnect? = null

  private data class ActiveConnect(
    val session: NativeMobileSession,
    val cancellation: NativeConnectCancellation,
    val epoch: Long,
  )

  private data class BackgroundLockRequest(
    val epoch: Long,
  )

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
    val attempt = synchronized(stateLock) {
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
      activeConnect = pending
      connectionState = NativeConnectionState.CONNECTING
      binding = null
      directoryReady = false
      pending
    }
    val active = attempt.session
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
      publishSnapshot()
      authenticated
    } catch (error: Throwable) {
      try {
        active.disconnect()
      } catch (_: Throwable) {
        // Preserve the original, sanitized connection failure.
      }
      synchronized(stateLock) {
        val current = activeConnect === attempt
        if (current) activeConnect = null
        if (
          current &&
          foreground &&
          lifecycleEpoch == attempt.epoch &&
          session === active
        ) {
          connectionState = NativeConnectionState.ERROR
          binding = null
          directoryReady = false
        }
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

  fun disconnect(): VeilMobileRuntimeSnapshot {
    val target = synchronized(stateLock) { session to lifecycleEpoch }
    val active = target.first
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
        directoryReady = false
      }
    }
    return publishSnapshot()
  }

  fun lockSession(): VeilMobileRuntimeSnapshot {
    val active = synchronized(stateLock) {
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
      directoryReady = false
      session.also { session = null }
    }
    publishSnapshot()
    try {
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
      directoryReady = false
      BackgroundLockRequest(lifecycleEpoch)
    }
    passStore.close()
    publishSnapshot()
    execute {
      finalizeBackgroundLock(request)
    }
  }

  private fun finalizeBackgroundLock(request: BackgroundLockRequest) {
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
        directoryReady = false
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
    val snapshot = snapshot()
    listeners.forEach { listener ->
      try {
        listener(snapshot)
      } catch (_: Throwable) {
        // One detached React context must not break native state publication.
      }
    }
    return snapshot
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
      binding = binding,
      pendingAccessPass = try {
        passStore.snapshot()
      } catch (_: Throwable) {
        null
      },
    )
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

  override fun signRestRequest(
    canonicalServerOrigin: String,
    method: String,
    requestTarget: String,
    body: ByteArray,
  ): NativeRestSignature =
    delegate.signRestRequest(canonicalServerOrigin, method, requestTarget, body).toNativeRestSignature()

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

internal fun MobileDirectRestRequest.toNativeDirectRestRequest(): NativeDirectRestRequest =
  NativeDirectRestRequest(requestToken = requestToken, requestTarget = requestTarget)

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
