package io.veil.mobile.runtime

import android.content.Context
import android.os.SystemClock
import androidx.annotation.VisibleForTesting
import io.veil.mobile.crypto.NativeIdentityVault
import io.veil.mobile.crypto.NativeIdentityVaultAccess
import java.io.File
import java.util.UUID
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import uniffi.veil_ffi.MobileAuthenticatedBinding
import uniffi.veil_ffi.MobileConnectCancellation
import uniffi.veil_ffi.MobileDirectConversationData
import uniffi.veil_ffi.MobileDirectDirectoryPageData
import uniffi.veil_ffi.MobileDirectHistoryNext
import uniffi.veil_ffi.MobileDirectHistoryOutcome
import uniffi.veil_ffi.MobileDirectHistoryProgress
import uniffi.veil_ffi.MobileDirectLiveBufferProgress
import uniffi.veil_ffi.MobileDirectLiveReplayProgress
import uniffi.veil_ffi.MobileDirectMessageData
import uniffi.veil_ffi.MobileDirectMessageDelivery
import uniffi.veil_ffi.MobileDirectMessageDirection
import uniffi.veil_ffi.MobileDirectMessageProjection
import uniffi.veil_ffi.MobileDirectMessageProjectionAvailability
import uniffi.veil_ffi.MobileDirectOwnPreKeyProgress
import uniffi.veil_ffi.MobileDirectPreKeyResult
import uniffi.veil_ffi.MobileDirectRestRequest
import uniffi.veil_ffi.MobileDirectSendReadiness
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

internal enum class NativeDirectHistoryState {
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
  SYNCING_HISTORY,
  HISTORY_SYNCHRONIZED,
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

internal data class NativeDirectHistoryNext(
  val request: NativeDirectRestRequest?,
  val historiesTerminal: Boolean,
)

internal enum class NativeDirectHistoryOutcome {
  IN_PROGRESS,
  COMPLETE,
  INCOMPLETE_SELF_HISTORY,
  CONVERSATION_REJECTED,
  STORAGE_UNCERTAIN,
}

internal data class NativeDirectHistoryProgress(
  val outcome: NativeDirectHistoryOutcome,
  val historiesTerminal: Boolean,
)

internal data class NativeDirectLiveBufferProgress(
  val bufferedEvents: Long,
  val historySynchronized: Boolean,
)

/** Aggregate-only result of one bounded native Direct live-replay turn. */
internal data class NativeDirectLiveReplayProgress(
  val consumed: Long,
  val projectionChanged: Boolean,
  val needsImmediatePump: Boolean,
  val ready: Boolean,
)

internal enum class NativeDirectMessageProjectionAvailability {
  AVAILABLE,
  UNAVAILABLE,
}

internal enum class NativeDirectMessageDirection {
  INCOMING,
  OUTGOING,
}

internal enum class NativeDirectMessageDelivery {
  SENDING,
  SENT,
  FAILED,
  UNKNOWN,
}

/**
 * Exact Direct preview row allowed to reach React Native. Cryptographic and
 * database fields are absent by construction.
 */
internal data class NativeDirectMessageView(
  val messageId: String,
  val text: String,
  val timestampMs: Long?,
  val direction: NativeDirectMessageDirection,
  val delivery: NativeDirectMessageDelivery,
) {
  override fun toString(): String =
    "NativeDirectMessageView(messageId=[REDACTED], text=[REDACTED], " +
      "timestampMs=$timestampMs, direction=$direction, delivery=$delivery)"
}

/** Opaque denial never echoes or enumerates a blocked conversation id. */
internal data class NativeDirectMessageProjection(
  val availability: NativeDirectMessageProjectionAvailability,
  val messages: List<NativeDirectMessageView>,
) {
  override fun toString(): String =
    "NativeDirectMessageProjection(availability=$availability, messages=${messages.size})"
}

private fun unavailableDirectMessageProjection() = NativeDirectMessageProjection(
  availability = NativeDirectMessageProjectionAvailability.UNAVAILABLE,
  messages = emptyList(),
)

private const val MAX_DIRECT_MESSAGE_TEXT_BYTES = 32 * 1024
private const val MAX_DIRECT_PROJECTION_TEXT_BYTES = 1024 * 1024

private fun String.boundedUtf8Length(maxBytes: Int): Int? {
  if (isEmpty()) return null
  var bytes = 0
  var index = 0
  while (index < length) {
    val character = this[index]
    val additional = when {
      character.code <= 0x7f -> 1
      character.code <= 0x7ff -> 2
      Character.isHighSurrogate(character) -> {
        if (index + 1 >= length || !Character.isLowSurrogate(this[index + 1])) return null
        index += 1
        4
      }
      Character.isLowSurrogate(character) -> return null
      else -> 3
    }
    if (bytes > maxBytes - additional) return null
    bytes += additional
    index += 1
  }
  return bytes
}

internal fun NativeDirectMessageProjection.isStructurallySafe(): Boolean {
  if (availability == NativeDirectMessageProjectionAvailability.UNAVAILABLE) {
    return messages.isEmpty()
  }
  if (messages.size > 100) return false
  val ids = HashSet<String>(messages.size)
  var totalTextBytes = 0
  return messages.all { message ->
    val parsedId = try {
      UUID.fromString(message.messageId)
    } catch (_: IllegalArgumentException) {
      null
    }
    val canonicalId = parsedId
      ?.takeUnless { it.mostSignificantBits == 0L && it.leastSignificantBits == 0L }
      ?.toString()
    val textBytes = message.text.boundedUtf8Length(MAX_DIRECT_MESSAGE_TEXT_BYTES)
      ?: return@all false
    if (totalTextBytes > MAX_DIRECT_PROJECTION_TEXT_BYTES - textBytes) return@all false
    totalTextBytes += textBytes
    canonicalId == message.messageId &&
      ids.add(message.messageId) &&
      message.timestampMs?.let { it in 0L..253_402_300_799_999L } != false
  }
}

internal fun <Handle : AutoCloseable, Output> mapAndCloseAllNativeHandles(
  handles: List<Handle>,
  mapper: (Handle) -> Output,
): List<Output> = try {
  handles.map(mapper)
} finally {
  handles.forEach { handle ->
    try {
      handle.close()
    } catch (_: Throwable) {
      // Every handle is attempted; UniFFI's cleaner remains a last resort.
    }
  }
}

private fun closeAllDirectMessageHandles(handles: List<MobileDirectMessageData>) {
  handles.forEach { handle ->
    try {
      handle.close()
    } catch (_: Throwable) {
      // Continue closing the remaining native plaintext owners.
    }
  }
}

internal enum class NativeDirectPreKeyInstallStatus {
  ESTABLISHED,
  ALREADY_ESTABLISHED,
}

internal data class NativeDirectPreKeyInstall(
  val status: NativeDirectPreKeyInstallStatus,
)

/** Native-authoritative readiness; never a Kotlin send capability. */
internal enum class NativeDirectSendReadiness {
  READY,
  NEEDS_PRE_KEY,
  UNAVAILABLE,
}

/** Opaque terminal result for one explicit Direct-session user action. */
internal sealed interface NativeDirectSessionActionResult {
  data class Success(val install: NativeDirectPreKeyInstall) : NativeDirectSessionActionResult

  data object Unavailable : NativeDirectSessionActionResult
}

internal fun interface NativeDirectSessionActionCallback {
  fun onComplete(result: NativeDirectSessionActionResult)
}

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
  /** Monotonic process-local capture order for stale RN event rejection. */
  val runtimeRevision: Long,
  /** Stable public identity of the current native Direct sync generation. */
  val directGeneration: Long?,
  /** Aggregate UI invalidation counter scoped to [directGeneration]. */
  val directContentRevision: Long?,
  val sessionState: NativeSessionState,
  val connectionState: NativeConnectionState,
  val directoryReady: Boolean,
  /** Coarse bootstrap progress; contains no keys, capabilities, targets, or response bytes. */
  val secureSyncState: NativeSecureSyncState,
  /** Native-only checkpoint used to enforce prekeys-before-directory ordering. */
  val ownPreKeyState: NativeOwnPreKeyState,
  /** Native-only checkpoint state; deliberately omitted from the RN payload. */
  val directDirectoryState: NativeDirectDirectoryState,
  /** Native-only history checkpoint; no cursors, message IDs, or errors cross to JS. */
  val directHistoryState: NativeDirectHistoryState,
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

  fun prepareNextDirectHistoryRequest(leaseToken: String): NativeDirectHistoryNext

  fun installDirectHistoryResponse(
    leaseToken: String,
    requestToken: String,
    response: ByteArray,
  ): NativeDirectHistoryProgress

  fun bufferDirectLiveEventsDuringSync(leaseToken: String): NativeDirectLiveBufferProgress

  fun replayDirectLiveEvents(leaseToken: String): NativeDirectLiveReplayProgress

  fun projectDirectMessages(conversationId: String): NativeDirectMessageProjection

  fun directSendReadiness(
    leaseToken: String,
    conversationId: String,
  ): NativeDirectSendReadiness

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
  private val executor: ScheduledExecutorService,
  private val databasePathProvider: () -> String,
  private val directLivePollIntervalMillis: Long = DIRECT_LIVE_IDLE_POLL_MILLIS,
  @get:VisibleForTesting
  private val peerPreKeyInstallBoundary: () -> Unit = {},
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

  init {
    require(directLivePollIntervalMillis in 10L..60_000L) {
      "Direct live poll interval is outside the supported bound"
    }
  }

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
  private var directHistoryState = NativeDirectHistoryState.IDLE
  private var directConversations: List<NativeDirectConversationInstall> = emptyList()
  // Process-scoped runtimes start without UI authority. Only an Activity
  // lifecycle transition may grant foreground access; this prevents a cold
  // headless process (for example future push handling) from opening the
  // encrypted account before any visible Veil surface exists.
  private var foreground = false
  private var lifecycleEpoch = 0L
  private var publicSnapshotRevision = 0L
  private var directGenerationCounter = 0L
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

  private class DirectProjectionTarget(
    val session: NativeMobileSession,
    val lifecycleEpoch: Long,
    val binding: PublicAuthenticatedBinding,
    val directSync: ActiveDirectSync,
  )

  private data class BackgroundLockRequest(
    val epoch: Long,
    val detachedDirectSync: DetachedDirectSync?,
  )

  private class ActiveDirectSync(
    val session: NativeMobileSession,
    val epoch: Long,
    val generation: Long,
    val leaseToken: String,
    val canonicalServerOrigin: String,
    val userId: String,
  ) {
    val conversations = LinkedHashMap<String, NativeDirectConversationInstall>()
    var pendingRequest: PendingDirectRequest? = null
    /** Exact user action reservation; never created by directory or replay. */
    var directSessionAction: PendingDirectSessionAction? = null
    var ownPreKeyRequestsPrepared = 0
    /** Guarded by [stateLock]; at most one delayed live turn exists per generation. */
    var liveReplayScheduled = false
    /** Guarded by [stateLock]; meaningful only within this exact generation. */
    var contentRevision = 0L

    override fun toString(): String =
      "ActiveDirectSync(epoch=$epoch, generation=$generation, " +
        "canonicalServerOrigin=$canonicalServerOrigin, " +
        "userId=$userId, leaseToken=[REDACTED], conversations=${conversations.size})"
  }

  private class PendingDirectRequest(
    val requestToken: String,
    val stage: DirectRequestStage,
    val method: NativeDirectHttpMethod,
    val lifecycleEpoch: Long,
    val generation: Long,
    val conversationId: String? = null,
    val directSessionAction: PendingDirectSessionAction? = null,
  ) {
    var call: NativeDirectHttpCall? = null

    override fun toString(): String =
      "PendingDirectRequest(" +
        "stage=$stage, method=$method, lifecycleEpoch=$lifecycleEpoch, " +
        "generation=$generation, conversationBound=${conversationId != null}, " +
        "requestToken=[REDACTED], " +
        "callAttached=${call != null})"
  }

  private class PendingDirectSessionAction(
    val lifecycleEpoch: Long,
    val generation: Long,
    val conversationId: String,
    val completion: DirectSessionActionCompletion,
  ) {
    override fun toString(): String =
      "PendingDirectSessionAction(" +
        "lifecycleEpoch=$lifecycleEpoch, generation=$generation, " +
        "conversationId=[REDACTED])"
  }

  private class DirectSessionActionCompletion(
    private val callback: NativeDirectSessionActionCallback,
  ) {
    private var completed = false

    fun complete(result: NativeDirectSessionActionResult): Boolean {
      val ownsCompletion = synchronized(this) {
        if (completed) false else {
          completed = true
          true
        }
      }
      if (!ownsCompletion) return false
      try {
        callback.onComplete(result)
      } catch (_: Throwable) {
        // A detached React context must not escape the native lifecycle gate.
      }
      return true
    }
  }

  private enum class DirectRequestStage {
    OWN_PREKEY,
    DIRECTORY,
    HISTORY,
    PEER_PREKEY,
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
    val directSessionCompletion: DirectSessionActionCompletion?,
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

  /**
   * Publish exactly one Direct through the native guarded projection.
   *
   * The SQLCipher read and native-to-Kotlin conversion run without
   * [stateLock]. The final exact-generation check and the narrow bridge
   * publisher run under one lock acquisition, so lifecycle revocation is
   * linearized strictly before an opaque denial or after Promise publication.
   * The callback must only serialize and resolve this one projection; it must
   * not retain the DTO or call back into the runtime.
   */
  fun publishDirectMessages(
    rawConversationId: String,
    publisher: (NativeDirectMessageProjection) -> Unit,
  ) {
    val conversationId = try {
      UUID.fromString(rawConversationId).toString()
    } catch (_: IllegalArgumentException) {
      publishUnavailableDirectMessages(publisher)
      return
    }
    if (conversationId != rawConversationId) {
      publishUnavailableDirectMessages(publisher)
      return
    }

    val target = synchronized(stateLock) {
      val active = session
      val currentBinding = binding
      val sync = activeDirectSync
      if (
        !foreground ||
        active == null ||
        currentBinding == null ||
        sync == null ||
        !isCurrentDirectSyncLocked(sync) ||
        sync.session !== active ||
        sessionState != NativeSessionState.OPEN ||
        connectionState != NativeConnectionState.CONNECTED ||
        !directoryReady ||
        !sync.conversations.containsKey(conversationId) ||
        directConversations.none { it.conversationId == conversationId }
      ) {
        null
      } else {
        DirectProjectionTarget(active, lifecycleEpoch, currentBinding, sync)
      }
    }
    if (target == null) {
      publishUnavailableDirectMessages(publisher)
      return
    }

    val projection = try {
      target.session.projectDirectMessages(conversationId)
    } catch (_: Throwable) {
      unavailableDirectMessageProjection()
    }
    val structurallySafe = projection.isStructurallySafe()
    synchronized(stateLock) {
      val selected = if (
        structurallySafe &&
        foreground &&
        session === target.session &&
        lifecycleEpoch == target.lifecycleEpoch &&
        binding == target.binding &&
        activeDirectSync === target.directSync &&
        isCurrentDirectSyncLocked(target.directSync) &&
        sessionState == NativeSessionState.OPEN &&
        connectionState == NativeConnectionState.CONNECTED &&
        directoryReady &&
        target.directSync.conversations.containsKey(conversationId) &&
        directConversations.any { it.conversationId == conversationId }
      ) {
        projection
      } else {
        unavailableDirectMessageProjection()
      }
      publisher(selected)
    }
  }

  private fun publishUnavailableDirectMessages(
    publisher: (NativeDirectMessageProjection) -> Unit,
  ) {
    synchronized(stateLock) {
      publisher(unavailableDirectMessageProjection())
    }
  }

  /**
   * Start one explicit, user-initiated peer-session action for the exact
   * selected conversation and public Direct generation.
   *
   * Directory installation, selection, projection, and live replay never call
   * this method. Kotlin does not infer readiness from the advisory directory
   * row and never mutates a ratchet. Native readiness either reports an
   * already-established session or owns the prepare/sign/install state
   * machine for one destructive, non-retried peer-prekey GET.
   */
  fun establishDirectSession(
    rawConversationId: String,
    expectedGeneration: Long,
    callback: NativeDirectSessionActionCallback,
  ) {
    val completion = DirectSessionActionCompletion(callback)
    val conversationId = try {
      UUID.fromString(rawConversationId).toString()
    } catch (_: IllegalArgumentException) {
      completion.complete(NativeDirectSessionActionResult.Unavailable)
      return
    }
    if (
      conversationId != rawConversationId ||
      expectedGeneration !in 1L..MAX_PUBLIC_SNAPSHOT_REVISION
    ) {
      completion.complete(NativeDirectSessionActionResult.Unavailable)
      return
    }

    val selection = synchronized(stateLock) {
      val sync = activeDirectSync
      if (
        sync == null ||
        sync.generation != expectedGeneration ||
        sync.pendingRequest != null ||
        sync.directSessionAction != null ||
        !isReadyDirectConversationLocked(sync, conversationId)
      ) {
        null
      } else {
        val action = PendingDirectSessionAction(
          lifecycleEpoch = lifecycleEpoch,
          generation = expectedGeneration,
          conversationId = conversationId,
          completion = completion,
        )
        sync.directSessionAction = action
        Pair(sync, action)
      }
    }
    if (selection == null) {
      completion.complete(NativeDirectSessionActionResult.Unavailable)
      return
    }
    val (sync, selected) = selection

    val readiness = try {
      sync.session.directSendReadiness(sync.leaseToken, conversationId)
    } catch (_: Throwable) {
      failDirectSync(sync)
      return
    }
    when (readiness) {
      NativeDirectSendReadiness.READY -> completeDirectSessionAction(
        sync,
        selected,
        NativeDirectPreKeyInstall(NativeDirectPreKeyInstallStatus.ALREADY_ESTABLISHED),
      )
      NativeDirectSendReadiness.NEEDS_PRE_KEY -> requestPeerPreKey(sync, selected)
      NativeDirectSendReadiness.UNAVAILABLE -> denyDirectSessionAction(sync, selected)
    }
  }

  private fun isReadyDirectConversationLocked(
    sync: ActiveDirectSync,
    conversationId: String,
  ): Boolean =
    isCurrentDirectSyncLocked(sync) &&
      sync.epoch == lifecycleEpoch &&
      ownPreKeyState == NativeOwnPreKeyState.PUBLISHED &&
      directDirectoryState == NativeDirectDirectoryState.SYNCHRONIZED &&
      directHistoryState == NativeDirectHistoryState.SYNCHRONIZED &&
      directoryReady &&
      sync.conversations.containsKey(conversationId) &&
      directConversations.any { conversation -> conversation.conversationId == conversationId }

  private fun requestPeerPreKey(
    sync: ActiveDirectSync,
    action: PendingDirectSessionAction,
  ) {
    val mayPrepare = synchronized(stateLock) {
      sync.pendingRequest == null &&
        sync.directSessionAction === action &&
        isReadyDirectConversationLocked(sync, action.conversationId)
    }
    if (!mayPrepare) {
      denyDirectSessionAction(sync, action)
      return
    }

    val prepared = try {
      sync.session.prepareDirectPreKeyRequest(sync.leaseToken, action.conversationId)
    } catch (_: Throwable) {
      // Rust may retain the outstanding capability before UniFFI lifts the
      // returned DTO. An exception is therefore an ambiguous post-retain
      // outcome, even when a concurrent incoming message made the ratchet
      // Ready. Only whole-lease revocation is safe across this bridge.
      failDirectSync(sync)
      return
    }
    val signed = try {
      prepareSignedDirectRequest(
        sync = sync,
        prepared = prepared,
        stage = DirectRequestStage.PEER_PREKEY,
        directSessionAction = action,
      )
    } catch (_: Throwable) {
      // Native prepare already returned an outstanding capability. Kotlin
      // validation or signing cannot prove that capability was consumed, even
      // when an incoming message concurrently made the ratchet Ready.
      failDirectSync(sync)
      return
    }
    val pending = signed.pending
    val call = try {
      directTransport.createCall(signed.httpRequest) { result ->
        enqueuePeerPreKeyResult(sync, pending, action, result)
      }
    } catch (_: Throwable) {
      signed.wipeWireBody()
      failDirectSync(sync)
      return
    } finally {
      signed.wipeWireBody()
    }

    val registered = synchronized(stateLock) {
      if (
        sync.pendingRequest == null &&
        sync.directSessionAction === action &&
        isReadyDirectConversationLocked(sync, action.conversationId) &&
        pending.lifecycleEpoch == action.lifecycleEpoch &&
        pending.generation == action.generation &&
        pending.conversationId == action.conversationId &&
        pending.directSessionAction === action
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
      // The signature has already been released. Even though the call never
      // started, only whole-lease revocation can prove that the native
      // outstanding capability will not be reused.
      failDirectSync(sync)
      return
    }
    try {
      call.start()
    } catch (_: Throwable) {
      failDirectSync(sync)
    }
  }

  private fun completeDirectSessionAction(
    sync: ActiveDirectSync,
    action: PendingDirectSessionAction,
    install: NativeDirectPreKeyInstall,
  ) {
    val accepted = synchronized(stateLock) {
      if (
        sync.directSessionAction !== action ||
        sync.pendingRequest != null ||
        !isReadyDirectConversationLocked(sync, action.conversationId)
      ) {
        false
      } else {
        sync.directSessionAction = null
        true
      }
    }
    if (accepted) {
      action.completion.complete(NativeDirectSessionActionResult.Success(install))
    }
  }

  private fun denyDirectSessionAction(
    sync: ActiveDirectSync,
    action: PendingDirectSessionAction,
  ) {
    val accepted = synchronized(stateLock) {
      if (sync.directSessionAction !== action || sync.pendingRequest != null) {
        false
      } else {
        sync.directSessionAction = null
        true
      }
    }
    if (accepted) {
      action.completion.complete(NativeDirectSessionActionResult.Unavailable)
    }
  }

  private fun enqueuePeerPreKeyResult(
    sync: ActiveDirectSync,
    pending: PendingDirectRequest,
    action: PendingDirectSessionAction,
    result: NativeDirectHttpResult,
  ) {
    try {
      executor.execute {
        handlePeerPreKeyResult(sync, pending, action, result)
      }
    } catch (_: Throwable) {
      result.wipeSensitiveBody()
      failDirectSync(sync)
    }
  }

  private fun handlePeerPreKeyResult(
    sync: ActiveDirectSync,
    pending: PendingDirectRequest,
    action: PendingDirectSessionAction,
    result: NativeDirectHttpResult,
  ) {
    try {
      val current = synchronized(stateLock) {
        sync.pendingRequest === pending &&
          sync.directSessionAction === action &&
          pending.stage == DirectRequestStage.PEER_PREKEY &&
          pending.lifecycleEpoch == action.lifecycleEpoch &&
          pending.generation == action.generation &&
          pending.conversationId == action.conversationId &&
          pending.directSessionAction === action &&
          isReadyDirectConversationLocked(sync, action.conversationId)
      }
      if (!current) return
      if (result !is NativeDirectHttpResult.Success) {
        // A destructive GET may have claimed the peer OPK before transport
        // failure. Revoke the whole lease; never retry it automatically.
        failDirectSync(sync)
        return
      }

      // Test-only empty production boundary makes the precheck/install race
      // deterministic. The second check and native mutation are intentionally
      // one stateLock critical section: background/reconnect either revokes
      // first and install never runs, or install completes before lifecycle
      // revocation can linearize.
      peerPreKeyInstallBoundary()
      val install = synchronized(stateLock) {
        if (
          sync.pendingRequest !== pending ||
          sync.directSessionAction !== action ||
          !isReadyDirectConversationLocked(sync, action.conversationId)
        ) {
          null
        } else {
          val installed = sync.session.installDirectPreKeyBundle(
            sync.leaseToken,
            pending.requestToken,
            action.conversationId,
            result.body,
          )
          sync.pendingRequest = null
          sync.directSessionAction = null
          installed
        }
      }
      if (install != null) {
        action.completion.complete(NativeDirectSessionActionResult.Success(install))
      }
    } catch (_: Throwable) {
      failDirectSync(sync)
    } finally {
      result.wipeSensitiveBody()
    }
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
      directHistoryState = NativeDirectHistoryState.IDLE
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
          directHistoryState = NativeDirectHistoryState.IDLE
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
      DetachedDirectSync(active, lease.leaseToken, null, null).cancelLeaseQuietly()
      throw VeilMobileRuntimeException("E_VEIL_SYNC", SECURE_DIRECT_BOOTSTRAP_ERROR)
    }

    val generation = synchronized(stateLock) {
      check(directGenerationCounter < MAX_PUBLIC_SNAPSHOT_REVISION) {
        "public Direct generation exhausted"
      }
      directGenerationCounter += 1
      directGenerationCounter
    }
    val sync = ActiveDirectSync(
      session = active,
      epoch = epoch,
      generation = generation,
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
        directHistoryState = NativeDirectHistoryState.IDLE
        directConversations = emptyList()
        directoryReady = false
        true
      } else {
        false
      }
    }
    if (!installed) {
      DetachedDirectSync(active, lease.leaseToken, null, null).cancelLeaseQuietly()
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

    pumpDirectLiveEvents(sync)
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

      // Re-observe the shared socket/deferred budget before this response can
      // mutate SQLCipher. A terminal epoch observed at this boundary aborts;
      // a concurrent terminal linearizes before/after the durable prefix.
      pumpDirectLiveEvents(sync)
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
            directHistoryState = NativeDirectHistoryState.IDLE
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

    pumpDirectLiveEvents(sync)
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
    directSessionAction: PendingDirectSessionAction? = null,
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
        DirectRequestStage.HISTORY -> {
          check(method == NativeDirectHttpMethod.GET) { "native Direct history method changed" }
          check(exactBody.isEmpty()) { "native Direct history body is not empty" }
          check(prepared.responseLimitBytes == NativeDirectHttpLimits.HISTORY_BYTES) {
            "native Direct history response bound changed"
          }
        }
        DirectRequestStage.PEER_PREKEY -> {
          val action = checkNotNull(directSessionAction) {
            "native Direct peer-prekey action is absent"
          }
          check(method == NativeDirectHttpMethod.GET) { "native Direct peer-prekey method changed" }
          check(exactBody.isEmpty()) { "native Direct peer-prekey body is not empty" }
          check(prepared.responseLimitBytes == NativeDirectHttpLimits.PREKEY_BYTES) {
            "native Direct peer-prekey response bound changed"
          }
          check(PEER_PREKEY_TARGET.matches(prepared.requestTarget)) {
            "native Direct peer-prekey target changed"
          }
          check(
            action.lifecycleEpoch == sync.epoch &&
              action.generation == sync.generation,
          ) { "native Direct peer-prekey action changed generation" }
        }
      }
      check(
        (stage == DirectRequestStage.PEER_PREKEY) == (directSessionAction != null),
      ) { "native Direct request action binding changed" }

      val signature = sync.session.signDirectRestRequest(sync.leaseToken, prepared.requestToken)
      check(signature.userId == sync.userId) { "native Direct signer returned a mismatched account" }
      val pending = PendingDirectRequest(
        requestToken = prepared.requestToken,
        stage = stage,
        method = method,
        lifecycleEpoch = sync.epoch,
        generation = sync.generation,
        conversationId = directSessionAction?.conversationId,
        directSessionAction = directSessionAction,
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

      pumpDirectLiveEvents(sync)
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
            directConversations = sync.conversations.values.sortedBy { conversation ->
              conversation.conversationId
            }
            directDirectoryState = NativeDirectDirectoryState.SYNCHRONIZED
            directHistoryState = NativeDirectHistoryState.SYNCING
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
        pumpDirectLiveEvents(sync)
        requestNextDirectHistoryPage(sync)
      } else {
        pumpDirectLiveEvents(sync)
        requestNextDirectDirectoryPage(sync)
      }
    } catch (_: Throwable) {
      result.wipeSensitiveBody()
      failDirectSync(sync)
    } finally {
      result.wipeSensitiveBody()
    }
  }

  private fun requestNextDirectHistoryPage(sync: ActiveDirectSync) {
    val mayPrepare = synchronized(stateLock) {
      isCurrentDirectSyncLocked(sync) &&
        sync.pendingRequest == null &&
        ownPreKeyState == NativeOwnPreKeyState.PUBLISHED &&
        directDirectoryState == NativeDirectDirectoryState.SYNCHRONIZED &&
        directHistoryState == NativeDirectHistoryState.SYNCING
    }
    if (!mayPrepare) return

    pumpDirectLiveEvents(sync)
    val next = sync.session.prepareNextDirectHistoryRequest(sync.leaseToken)
    if (next.historiesTerminal) {
      check(next.request == null) { "terminal native Direct history returned a request" }
      val accepted = synchronized(stateLock) {
        if (
          !isCurrentDirectSyncLocked(sync) ||
          sync.pendingRequest != null ||
          directHistoryState != NativeDirectHistoryState.SYNCING
        ) {
          false
        } else {
          directHistoryState = NativeDirectHistoryState.SYNCHRONIZED
          // Even an empty history remains behind the authenticated live-replay
          // barrier until Rust explicitly observes the shared FIFO quiescent.
          directoryReady = false
          true
        }
      }
      if (accepted) {
        publishSnapshot()
        continueDirectLiveReplay(sync)
      }
      return
    }

    val prepared = checkNotNull(next.request) { "in-progress native Direct history omitted its request" }
    val signed = prepareSignedDirectRequest(sync, prepared, DirectRequestStage.HISTORY)
    val pending = signed.pending
    val call = try {
      directTransport.createCall(signed.httpRequest) { result ->
        enqueueDirectHistoryResult(sync, pending, result)
      }
    } finally {
      signed.wipeWireBody()
    }
    val registered = synchronized(stateLock) {
      if (
        isCurrentDirectSyncLocked(sync) &&
        sync.pendingRequest == null &&
        directHistoryState == NativeDirectHistoryState.SYNCING
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

  private fun enqueueDirectHistoryResult(
    sync: ActiveDirectSync,
    pending: PendingDirectRequest,
    result: NativeDirectHttpResult,
  ) {
    try {
      executor.execute {
        handleDirectHistoryResult(sync, pending, result)
      }
    } catch (_: RuntimeException) {
      result.wipeSensitiveBody()
    }
  }

  private fun handleDirectHistoryResult(
    sync: ActiveDirectSync,
    pending: PendingDirectRequest,
    result: NativeDirectHttpResult,
  ) {
    try {
      val current = synchronized(stateLock) {
        isCurrentDirectSyncLocked(sync) &&
          sync.pendingRequest === pending &&
          pending.stage == DirectRequestStage.HISTORY &&
          directHistoryState == NativeDirectHistoryState.SYNCING
      }
      if (!current) return
      if (result !is NativeDirectHttpResult.Success) {
        failDirectSync(sync)
        return
      }

      pumpDirectLiveEvents(sync)
      val progress = sync.session.installDirectHistoryResponse(
        sync.leaseToken,
        pending.requestToken,
        result.body,
      )
      check(progress.outcome != NativeDirectHistoryOutcome.STORAGE_UNCERTAIN) {
        "native Direct history storage became uncertain"
      }
      check(
        progress.outcome != NativeDirectHistoryOutcome.IN_PROGRESS ||
          !progress.historiesTerminal,
      ) { "native Direct history progress contradicted its terminal checkpoint" }
      val accepted = synchronized(stateLock) {
        if (!isCurrentDirectSyncLocked(sync) || sync.pendingRequest !== pending) {
          false
        } else {
          sync.pendingRequest = null
          if (progress.historiesTerminal) {
            directHistoryState = NativeDirectHistoryState.SYNCHRONIZED
          }
          directoryReady = false
          true
        }
      }
      if (!accepted) return

      if (progress.historiesTerminal) {
        publishSnapshot()
        continueDirectLiveReplay(sync)
      } else {
        pumpDirectLiveEvents(sync)
        requestNextDirectHistoryPage(sync)
      }
    } catch (_: Throwable) {
      failDirectSync(sync)
    } finally {
      result.wipeSensitiveBody()
    }
  }

  /**
   * Explicit bounded pump at every native HTTP/lifecycle boundary.
   *
   * Socket and deferred entries retain one shared Rust permit, so a periodic
   * timer cannot create capacity; it would only observe an already-terminal
   * epoch sooner while adding another lifecycle race. Boundary pumps provide
   * the mutation linearization point, and producer-side limits remain active
   * continuously while HTTP is in flight.
   */
  private fun pumpDirectLiveEvents(sync: ActiveDirectSync): NativeDirectLiveBufferProgress {
    val current = synchronized(stateLock) { isCurrentDirectSyncLocked(sync) }
    if (!current) {
      throw IllegalStateException("native Direct live pump used after lifecycle revocation")
    }
    val progress = sync.session.bufferDirectLiveEventsDuringSync(sync.leaseToken)
    check(progress.bufferedEvents in 0..MAX_BUFFERED_DIRECT_EVENTS_PER_PUMP) {
      "native Direct live pump count exceeded its shared bound"
    }
    return progress
  }

  /**
   * Advance exactly one bounded history-to-live replay turn. Full native
   * batches are rescheduled onto the serialized runtime executor, keeping a
   * lifecycle check between every 64 authenticated events. Direct projections
   * remain closed until native explicitly observes quiescence.
   */
  private fun continueDirectLiveReplay(sync: ActiveDirectSync) {
    try {
      val current = synchronized(stateLock) {
        isCurrentDirectSyncLocked(sync) &&
          sync.pendingRequest == null &&
          ownPreKeyState == NativeOwnPreKeyState.PUBLISHED &&
          directDirectoryState == NativeDirectDirectoryState.SYNCHRONIZED &&
          directHistoryState == NativeDirectHistoryState.SYNCHRONIZED &&
          !directoryReady
      }
      if (!current) return

      val progress = sync.session.replayDirectLiveEvents(sync.leaseToken)
      check(progress.consumed in 0..MAX_DIRECT_LIVE_REPLAY_EVENTS_PER_TURN) {
        "native Direct live replay count exceeded its shared bound"
      }
      if (!progress.ready) {
        check(
          progress.needsImmediatePump &&
            progress.consumed == MAX_DIRECT_LIVE_REPLAY_EVENTS_PER_TURN,
        ) { "native Direct live replay returned an invalid draining checkpoint" }
        executor.execute { continueDirectLiveReplay(sync) }
        return
      }
      check(!progress.needsImmediatePump) {
        "initial native Direct live replay reached Ready before quiescence"
      }

      val accepted = synchronized(stateLock) {
        if (
          !isCurrentDirectSyncLocked(sync) ||
          sync.pendingRequest != null ||
          directHistoryState != NativeDirectHistoryState.SYNCHRONIZED
        ) {
          false
        } else {
          directoryReady = true
          true
        }
      }
      if (accepted) publishSnapshot()
      if (accepted) scheduleContinuousDirectLiveReplay(sync)
    } catch (_: Throwable) {
      failDirectSync(sync)
    }
  }

  /**
   * Keep the authenticated Direct FIFO draining after the history handoff.
   *
   * Rust remains the sole event/ACK reconciler and consumes at most 64 entries
   * per turn. Kotlin only schedules another exact-generation turn. Lifecycle
   * revocation makes an already scheduled task a no-op, while a full batch is
   * continued immediately so the shared bounded queue cannot be starved.
   */
  private fun scheduleContinuousDirectLiveReplay(
    sync: ActiveDirectSync,
    delayMillis: Long = directLivePollIntervalMillis,
  ) {
    val shouldSchedule = synchronized(stateLock) {
      if (
        !isCurrentDirectSyncLocked(sync) ||
        !directoryReady ||
        ownPreKeyState != NativeOwnPreKeyState.PUBLISHED ||
        directDirectoryState != NativeDirectDirectoryState.SYNCHRONIZED ||
        directHistoryState != NativeDirectHistoryState.SYNCHRONIZED ||
        sync.liveReplayScheduled
      ) {
        false
      } else {
        sync.liveReplayScheduled = true
        true
      }
    }
    if (!shouldSchedule) return

    try {
      executor.schedule(
        { runContinuousDirectLiveReplay(sync) },
        delayMillis.coerceAtLeast(0L),
        TimeUnit.MILLISECONDS,
      )
    } catch (_: RuntimeException) {
      synchronized(stateLock) {
        if (activeDirectSync === sync) sync.liveReplayScheduled = false
      }
      failDirectSync(sync)
    }
  }

  private fun runContinuousDirectLiveReplay(sync: ActiveDirectSync) {
    val current = synchronized(stateLock) {
      if (activeDirectSync === sync) sync.liveReplayScheduled = false
      isCurrentDirectSyncLocked(sync) &&
        directoryReady &&
        ownPreKeyState == NativeOwnPreKeyState.PUBLISHED &&
        directDirectoryState == NativeDirectDirectoryState.SYNCHRONIZED &&
        directHistoryState == NativeDirectHistoryState.SYNCHRONIZED
    }
    if (!current) return

    try {
      val progress = sync.session.replayDirectLiveEvents(sync.leaseToken)
      check(progress.consumed in 0..MAX_DIRECT_LIVE_REPLAY_EVENTS_PER_TURN) {
        "continuous native Direct replay count exceeded its shared bound"
      }
      check(progress.ready) {
        "continuous native Direct replay revoked the Ready checkpoint"
      }
      if (progress.needsImmediatePump) {
        check(progress.consumed == MAX_DIRECT_LIVE_REPLAY_EVENTS_PER_TURN) {
          "continuous native Direct replay requested an invalid immediate turn"
        }
      }

      val stillCurrent = synchronized(stateLock) {
        if (!isCurrentDirectSyncLocked(sync) || !directoryReady) {
          false
        } else {
          if (progress.projectionChanged) {
            check(sync.contentRevision < MAX_PUBLIC_SNAPSHOT_REVISION) {
              "public Direct content revision exhausted"
            }
            sync.contentRevision += 1
          }
          true
        }
      }
      if (!stillCurrent) return
      if (progress.projectionChanged) publishSnapshot()
      scheduleContinuousDirectLiveReplay(
        sync,
        if (progress.needsImmediatePump) 0L else directLivePollIntervalMillis,
      )
    } catch (_: Throwable) {
      failDirectSync(sync)
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
    val directSessionCompletion = selected?.directSessionAction?.completion
    // Cancel under the same lock that revokes the generation. This closes the
    // tiny attach-before-start window: once lifecycle/reconnect has linearized
    // here, a still-unstarted call is terminal before the requester can start
    // it. The out-of-lock cancellation below remains an idempotent fallback.
    pendingCall?.cancelQuietly()
    selected?.pendingRequest = null
    selected?.directSessionAction = null
    ownPreKeyState = if (nextState == NativeDirectDirectoryState.ERROR) {
      NativeOwnPreKeyState.ERROR
    } else {
      NativeOwnPreKeyState.IDLE
    }
    directDirectoryState = nextState
    directHistoryState = if (nextState == NativeDirectDirectoryState.ERROR) {
      NativeDirectHistoryState.ERROR
    } else {
      NativeDirectHistoryState.IDLE
    }
    directConversations = emptyList()
    directoryReady = false
    return selected?.let { sync ->
      DetachedDirectSync(
        sync.session,
        sync.leaseToken,
        pendingCall,
        directSessionCompletion,
      )
    }
  }

  private fun DetachedDirectSync?.cancelHttpQuietly() {
    val selected = this ?: return
    try {
      selected.pendingCall?.cancel()
    } catch (_: Throwable) {
      // Detaching remains terminal even if the HTTP call already completed.
    } finally {
      selected.directSessionCompletion?.complete(
        NativeDirectSessionActionResult.Unavailable,
      )
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
    check(publicSnapshotRevision < MAX_PUBLIC_SNAPSHOT_REVISION) {
      "public mobile runtime snapshot revision exhausted"
    }
    publicSnapshotRevision += 1
    val identityExists = session != null || try {
      vault.hasIdentity()
    } catch (_: Throwable) {
      false
    }
    return VeilMobileRuntimeSnapshot(
      identityExists = identityExists,
      runtimeRevision = publicSnapshotRevision,
      directGeneration = activeDirectSync?.generation,
      directContentRevision = activeDirectSync?.contentRevision,
      sessionState = sessionState,
      connectionState = connectionState,
      directoryReady = directoryReady,
      secureSyncState = secureSyncStateLocked(),
      ownPreKeyState = ownPreKeyState,
      directDirectoryState = directDirectoryState,
      directHistoryState = directHistoryState,
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
      directDirectoryState == NativeDirectDirectoryState.ERROR ||
      directHistoryState == NativeDirectHistoryState.ERROR -> NativeSecureSyncState.ERROR
    ownPreKeyState == NativeOwnPreKeyState.CHECKING ||
      ownPreKeyState == NativeOwnPreKeyState.PUBLISHING -> NativeSecureSyncState.PUBLISHING_KEYS
    directDirectoryState == NativeDirectDirectoryState.SYNCING -> NativeSecureSyncState.SYNCING_DIRECTORY
    directHistoryState == NativeDirectHistoryState.SYNCING -> NativeSecureSyncState.SYNCING_HISTORY
    directHistoryState == NativeDirectHistoryState.SYNCHRONIZED ->
      NativeSecureSyncState.HISTORY_SYNCHRONIZED
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
    private val PEER_PREKEY_TARGET = Regex("^/v1/prekeys/[0-9a-f]{64}$")
    private const val MAX_OWN_PREKEY_REQUESTS = 2
    private const val SECURE_DIRECT_BOOTSTRAP_ERROR = "Unable to complete the secure Direct bootstrap"
    private const val MAX_DIRECT_CONVERSATIONS = 10_000
    private const val MAX_BUFFERED_DIRECT_EVENTS_PER_PUMP = 4_096L
    private const val MAX_DIRECT_LIVE_REPLAY_EVENTS_PER_TURN = 64L
    private const val MAX_PUBLIC_SNAPSHOT_REVISION = 9_007_199_254_740_991L

    private const val DIRECT_LIVE_IDLE_POLL_MILLIS = 250L

    private fun newRuntimeExecutor(): ScheduledExecutorService =
      Executors.newSingleThreadScheduledExecutor { operation ->
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

  override fun prepareNextDirectHistoryRequest(leaseToken: String): NativeDirectHistoryNext =
    delegate.prepareNextDirectHistoryRequest(leaseToken).toNativeDirectHistoryNext()

  override fun installDirectHistoryResponse(
    leaseToken: String,
    requestToken: String,
    response: ByteArray,
  ): NativeDirectHistoryProgress =
    delegate.installDirectHistoryResponse(leaseToken, requestToken, response)
      .toNativeDirectHistoryProgress()

  override fun bufferDirectLiveEventsDuringSync(leaseToken: String): NativeDirectLiveBufferProgress =
    delegate.bufferDirectLiveEventsDuringSync(leaseToken).toNativeDirectLiveBufferProgress()

  override fun replayDirectLiveEvents(leaseToken: String): NativeDirectLiveReplayProgress =
    delegate.replayDirectLiveEvents(leaseToken).toNativeDirectLiveReplayProgress()

  override fun projectDirectMessages(conversationId: String): NativeDirectMessageProjection =
    delegate.projectDirectMessages(conversationId).toNativeDirectMessageProjection()

  override fun directSendReadiness(
    leaseToken: String,
    conversationId: String,
  ): NativeDirectSendReadiness =
    delegate.directSendReadiness(leaseToken, conversationId).toNativeDirectSendReadiness()

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

internal fun MobileDirectHistoryNext.toNativeDirectHistoryNext(): NativeDirectHistoryNext =
  NativeDirectHistoryNext(
    request = request?.toNativeDirectRestRequest(),
    historiesTerminal = historiesTerminal,
  )

internal fun MobileDirectHistoryProgress.toNativeDirectHistoryProgress(): NativeDirectHistoryProgress =
  NativeDirectHistoryProgress(
    outcome = when (outcome) {
      MobileDirectHistoryOutcome.IN_PROGRESS -> NativeDirectHistoryOutcome.IN_PROGRESS
      MobileDirectHistoryOutcome.COMPLETE -> NativeDirectHistoryOutcome.COMPLETE
      MobileDirectHistoryOutcome.INCOMPLETE_SELF_HISTORY ->
        NativeDirectHistoryOutcome.INCOMPLETE_SELF_HISTORY
      MobileDirectHistoryOutcome.CONVERSATION_REJECTED ->
        NativeDirectHistoryOutcome.CONVERSATION_REJECTED
      MobileDirectHistoryOutcome.STORAGE_UNCERTAIN -> NativeDirectHistoryOutcome.STORAGE_UNCERTAIN
    },
    historiesTerminal = historiesTerminal,
  )

internal fun MobileDirectLiveBufferProgress.toNativeDirectLiveBufferProgress(): NativeDirectLiveBufferProgress =
  NativeDirectLiveBufferProgress(
    bufferedEvents = bufferedEvents.toLong(),
    historySynchronized = historySynchronized,
  )

internal fun MobileDirectLiveReplayProgress.toNativeDirectLiveReplayProgress(): NativeDirectLiveReplayProgress =
  NativeDirectLiveReplayProgress(
    consumed = consumed.toLong(),
    projectionChanged = projectionChanged,
    needsImmediatePump = needsImmediatePump,
    ready = ready,
  )

internal fun MobileDirectMessageProjection.toNativeDirectMessageProjection(): NativeDirectMessageProjection {
  if (availability == MobileDirectMessageProjectionAvailability.UNAVAILABLE) {
    closeAllDirectMessageHandles(messages)
    return unavailableDirectMessageProjection()
  }
  return try {
    NativeDirectMessageProjection(
      availability = NativeDirectMessageProjectionAvailability.AVAILABLE,
      messages = mapAndCloseAllNativeHandles(
        messages,
        MobileDirectMessageData::toNativeDirectMessageView,
      ),
    )
  } catch (_: Throwable) {
    unavailableDirectMessageProjection()
  }
}

private fun MobileDirectMessageData.toNativeDirectMessageView(): NativeDirectMessageView =
  NativeDirectMessageView(
    messageId = messageId(),
    text = text(),
    timestampMs = timestampMs(),
    direction = when (direction()) {
      MobileDirectMessageDirection.INCOMING -> NativeDirectMessageDirection.INCOMING
      MobileDirectMessageDirection.OUTGOING -> NativeDirectMessageDirection.OUTGOING
    },
    delivery = when (delivery()) {
      MobileDirectMessageDelivery.SENDING -> NativeDirectMessageDelivery.SENDING
      MobileDirectMessageDelivery.SENT -> NativeDirectMessageDelivery.SENT
      MobileDirectMessageDelivery.FAILED -> NativeDirectMessageDelivery.FAILED
      MobileDirectMessageDelivery.UNKNOWN -> NativeDirectMessageDelivery.UNKNOWN
    },
  )

internal fun MobileDirectPreKeyResult.toNativeDirectPreKeyInstall(): NativeDirectPreKeyInstall =
  NativeDirectPreKeyInstall(
    status = when (status) {
      "established" -> NativeDirectPreKeyInstallStatus.ESTABLISHED
      "already_established" -> NativeDirectPreKeyInstallStatus.ALREADY_ESTABLISHED
      else -> throw IllegalStateException("native Direct prekey install returned an unsupported status")
    },
  )

internal fun MobileDirectSendReadiness.toNativeDirectSendReadiness(): NativeDirectSendReadiness =
  when (this) {
    MobileDirectSendReadiness.READY -> NativeDirectSendReadiness.READY
    MobileDirectSendReadiness.NEEDS_PRE_KEY -> NativeDirectSendReadiness.NEEDS_PRE_KEY
    MobileDirectSendReadiness.UNAVAILABLE -> NativeDirectSendReadiness.UNAVAILABLE
  }

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
