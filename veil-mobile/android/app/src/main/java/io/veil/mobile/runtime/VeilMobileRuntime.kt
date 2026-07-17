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

internal interface NativeMobileSession : AutoCloseable {
  fun connect(websocketUrl: String, canonicalOrigin: String): PublicAuthenticatedBinding

  fun connectWithNodeAccessPass(
    websocketUrl: String,
    canonicalOrigin: String,
    nodeAccessPass: ByteArray,
  ): PublicAuthenticatedBinding

  fun disconnect()
}

internal fun interface NativeMobileSessionFactory {
  fun create(mnemonicUtf8: ByteArray, databasePath: String): NativeMobileSession
}

internal class VeilMobileRuntime internal constructor(
  private val vault: NativeIdentityVaultAccess,
  private val passStore: NodeAccessPassStore,
  private val sessionFactory: NativeMobileSessionFactory,
  private val executor: ExecutorService,
  private val databasePathProvider: () -> String,
) {
  constructor(context: Context) : this(
    vault = NativeIdentityVault(context.applicationContext),
    passStore = NodeAccessPassStore(clockMillis = { SystemClock.elapsedRealtime() }),
    sessionFactory = UniFfiMobileSessionFactory,
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
    synchronized(stateLock) {
      if (session != null && sessionState == NativeSessionState.OPEN) return snapshotLocked()
      sessionState = NativeSessionState.OPENING
      connectionState = NativeConnectionState.DISCONNECTED
      binding = null
      directoryReady = false
    }
    publishSnapshot()

    var candidate: NativeMobileSession? = null
    try {
      candidate = vault.withMnemonicBytes { mnemonicUtf8 ->
        sessionFactory.create(mnemonicUtf8, databasePathProvider())
      }
      synchronized(stateLock) {
        session?.closeQuietly()
        session = candidate
        candidate = null
        sessionState = NativeSessionState.OPEN
        connectionState = NativeConnectionState.DISCONNECTED
      }
      return publishSnapshot()
    } catch (_: Throwable) {
      candidate?.closeQuietly()
      synchronized(stateLock) {
        session = null
        sessionState = NativeSessionState.ERROR
        connectionState = NativeConnectionState.DISCONNECTED
        binding = null
        directoryReady = false
      }
      publishSnapshot()
      throw VeilMobileRuntimeException("E_VEIL_OPEN", "Unable to open the encrypted local account")
    }
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
    val active = synchronized(stateLock) {
      session ?: throw VeilMobileRuntimeException("E_VEIL_LOCKED", "Open the local account before connecting")
    }
    try {
      active.disconnect()
    } catch (_: Throwable) {
      // A stale transport must not prevent a fresh, serialized connection.
    }
    synchronized(stateLock) {
      connectionState = NativeConnectionState.CONNECTING
      binding = null
      directoryReady = false
    }
    publishSnapshot()

    return try {
      val authenticated = if (accessAttempt == null) {
        active.connect(origin.websocketUrl, origin.value)
      } else {
        active.connectWithNodeAccessPass(origin.websocketUrl, origin.value, accessAttempt.token)
      }
      synchronized(stateLock) {
        binding = authenticated
        connectionState = NativeConnectionState.CONNECTED
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
        connectionState = NativeConnectionState.ERROR
        binding = null
        directoryReady = false
      }
      publishSnapshot()
      throw publicConnectError(error)
    }
  }

  fun disconnect(): VeilMobileRuntimeSnapshot {
    val active = synchronized(stateLock) { session }
    try {
      active?.disconnect()
    } catch (_: Throwable) {
      synchronized(stateLock) {
        connectionState = NativeConnectionState.ERROR
        binding = null
        directoryReady = false
      }
      publishSnapshot()
      throw VeilMobileRuntimeException("E_VEIL_DISCONNECT", "Unable to close the Veil Node connection cleanly")
    }
    synchronized(stateLock) {
      connectionState = NativeConnectionState.DISCONNECTED
      binding = null
      directoryReady = false
    }
    return publishSnapshot()
  }

  fun lockSession(): VeilMobileRuntimeSnapshot {
    val active = synchronized(stateLock) {
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

  fun lockForBackground() {
    execute {
      try {
        lockSession()
      } catch (_: Throwable) {
        // There is no safe UI target while backgrounding; teardown is already
        // fail-closed and the process will reclaim remaining native memory.
      }
    }
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
    val identityExists = try {
      vault.hasIdentity()
    } catch (_: Throwable) {
      sessionState = NativeSessionState.ERROR
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

private class UniFfiMobileSession(
  private val delegate: VeilMobileSession,
) : NativeMobileSession {
  override fun connect(websocketUrl: String, canonicalOrigin: String): PublicAuthenticatedBinding =
    delegate.connect(websocketUrl, canonicalOrigin).toPublicBinding()

  override fun connectWithNodeAccessPass(
    websocketUrl: String,
    canonicalOrigin: String,
    nodeAccessPass: ByteArray,
  ): PublicAuthenticatedBinding =
    delegate.connectWithNodeAccessPass(websocketUrl, canonicalOrigin, nodeAccessPass).toPublicBinding()

  override fun disconnect() {
    delegate.disconnect()
  }

  override fun close() {
    delegate.close()
  }
}

private fun MobileAuthenticatedBinding.toPublicBinding(): PublicAuthenticatedBinding =
  PublicAuthenticatedBinding(canonicalServerOrigin = canonicalServerOrigin, userId = userId)

private fun NativeMobileSession.closeQuietly() {
  try {
    close()
  } catch (_: Throwable) {
    // Explicit teardown is best effort; the UniFFI cleaner remains a fallback.
  }
}
