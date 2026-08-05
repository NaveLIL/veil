package io.veil.mobile.runtime

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

private const val DIRECT_SESSION_ERROR_CODE = "E_VEIL_DIRECT_SESSION"
private const val DIRECT_SESSION_ERROR = "Unable to establish the secure Direct session"
private const val DIRECT_SEND_REJECTED_CODE = "E_VEIL_DIRECT_SEND_REJECTED"
private const val DIRECT_SEND_UNAVAILABLE_CODE = "E_VEIL_DIRECT_SEND_UNAVAILABLE"
private const val DIRECT_SEND_UNAVAILABLE = "Direct messaging is unavailable"
private const val PUBLIC_FAILURE_CODE_KEY = "publicFailureCodeV1"
private const val RUNTIME_FAILURE_MESSAGE = "Native mobile runtime operation failed"

internal class VeilMobileRuntimeModule(
  context: ReactApplicationContext,
  private val runtime: VeilMobileRuntime,
) : ReactContextBaseJavaModule(context) {
  private val listenerCount = AtomicInteger(0)
  private val runtimeListener: (VeilMobileRuntimeSnapshot) -> Unit = { snapshot ->
    if (listenerCount.get() > 0 && reactApplicationContext.hasActiveReactInstance()) {
      reactApplicationContext
        .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
        .emit(EVENT_STATE_CHANGED, snapshot.toWritableMap())
    }
  }

  override fun getName(): String = "VeilMobileRuntime"

  override fun initialize() {
    super.initialize()
    runtime.addListener(runtimeListener)
  }

  override fun invalidate() {
    runtime.removeListener(runtimeListener)
    listenerCount.set(0)
    super.invalidate()
  }

  @ReactMethod
  fun getRuntimeSnapshot(promise: Promise) = onRuntime(promise) {
    runtime.snapshot().toWritableMap()
  }

  @ReactMethod
  fun verifyIdentityPresence(promise: Promise) = onRuntime(promise) {
    runtime.verifyIdentityPresence()
  }

  @ReactMethod
  fun openSession(promise: Promise) = onRuntime(promise) {
    runtime.openSession().toWritableMap()
  }

  @ReactMethod
  fun connect(canonicalOrigin: String, promise: Promise) = onRuntime(promise) {
    runtime.connect(canonicalOrigin).toWritableMap()
  }

  @ReactMethod
  fun connectPendingAccessPass(flowId: String, promise: Promise) = onRuntime(promise) {
    runtime.connectPendingAccessPass(flowId).toWritableMap()
  }

  @ReactMethod
  fun disconnect(promise: Promise) = onRuntime(promise) {
    runtime.disconnect().toWritableMap()
  }

  @ReactMethod
  fun lockSession(promise: Promise) = onRuntime(promise) {
    // JavaScript calls this only from AppState. The process-wide Activity gate
    // owns the authoritative fail-closed lock, so a delayed callback from an
    // older inactive event must not revoke a newer native foreground epoch.
    runtime.lockSessionIfBackground().toWritableMap()
  }

  @ReactMethod
  fun cancelPendingAccessPass(flowId: String, promise: Promise) = onRuntime(promise) {
    runtime.cancelPendingAccessPass(flowId)
  }

  @ReactMethod
  fun startWsEventsForegroundService(promise: Promise) = onRuntime(promise) {
    val context = reactApplicationContext
    androidx.core.content.ContextCompat.startForegroundService(
      context,
      android.content.Intent(context, VeilEventsService::class.java)
    )
    true
  }

  @ReactMethod
  fun projectDirectMessages(conversationId: String, promise: Promise) = onRuntimePublication(promise) {
    runtime.publishDirectMessages(conversationId) { projection ->
      promise.resolve(projection.toWritableMap())
    }
  }

  @ReactMethod
  fun getDirectIdentityVerification(
    conversationId: String,
    expectedDirectGeneration: Double,
    promise: Promise,
  ) = onRuntimePublication(promise) {
    val generation = expectedDirectGeneration.toSafeDirectGenerationOrNull()
    if (generation == null) {
      promise.resolve(null)
    } else {
      runtime.publishDirectIdentityVerification(conversationId, generation, null) { verification ->
        promise.resolve(verification?.toWritableMap())
      }
    }
  }

  @ReactMethod
  fun confirmDirectIdentityVerification(
    conversationId: String,
    expectedDirectGeneration: Double,
    expectedFingerprintHex: String,
    promise: Promise,
  ) = onRuntimePublication(promise) {
    val generation = expectedDirectGeneration.toSafeDirectGenerationOrNull()
    if (generation == null) {
      promise.resolve(null)
    } else {
      runtime.publishDirectIdentityVerification(
        conversationId,
        generation,
        expectedFingerprintHex,
      ) { verification ->
        promise.resolve(verification?.toWritableMap())
      }
    }
  }

  @ReactMethod
  fun confirmDirectIdentityVerificationQr(
    conversationId: String,
    expectedDirectGeneration: Double,
    scannedQrPayload: String,
    promise: Promise,
  ) = onRuntimePublication(promise) {
    val generation = expectedDirectGeneration.toSafeDirectGenerationOrNull()
    if (generation == null) {
      promise.resolve(null)
    } else {
      runtime.publishDirectIdentityVerificationQr(
        conversationId,
        generation,
        scannedQrPayload,
      ) { verification ->
        promise.resolve(verification?.toWritableMap())
      }
    }
  }

  /**
   * Explicit UI action only. The caller must bind the selected conversation to
   * the exact generation published in the same runtime snapshot.
   */
  @ReactMethod
  fun establishDirectSession(
    conversationId: String,
    expectedDirectGeneration: Double,
    promise: Promise,
  ) = onRuntimePublication(promise) {
    val generation = expectedDirectGeneration.toSafeDirectGenerationOrNull()
      ?: throw VeilMobileRuntimeException(DIRECT_SESSION_ERROR_CODE, DIRECT_SESSION_ERROR)
    runtime.establishDirectSession(conversationId, generation) { result ->
      promise.publishDirectSessionResult(result)
    }
  }

  /**
   * Accept one explicit text intent for the exact native Direct generation.
   * Success is deliberately payload-free: message identity, sequence,
   * ciphertext, and timestamps remain owned by Rust and SQLCipher.
   */
  @ReactMethod
  fun sendDirectText(
    conversationId: String,
    expectedDirectGeneration: Double,
    text: String,
    promise: Promise,
  ) = onRuntimePublication(promise) {
    val generation = expectedDirectGeneration.toSafeDirectGenerationOrNull()
      ?: throw VeilMobileRuntimeException(DIRECT_SEND_UNAVAILABLE_CODE, DIRECT_SEND_UNAVAILABLE)
    runtime.sendDirectText(conversationId, generation, text) { result ->
      promise.publishDirectTextSendResult(result)
    }
  }

  @ReactMethod
  fun prepareContactSearch(username: String, promise: Promise) = onRuntime(promise) {
    val req = runtime.prepareContactSearchRequest(username)
    val sigMap = Arguments.createMap().apply {
      putString("version", req.signature.version)
      putString("userId", req.signature.userId)
      putString("timestampMs", req.signature.timestampMs)
      putString("nonceBase64url", req.signature.nonceBase64url)
      putString("signatureBase64url", req.signature.signatureBase64url)
    }
    Arguments.createMap().apply {
      putString("method", req.method)
      putString("target", req.requestTarget)
      putMap("signature", sigMap)
    }
  }

  @ReactMethod
  fun prepareCreateDirect(peerUserId: String, promise: Promise) = onRuntime(promise) {
    val req = runtime.prepareCreateDirectRequest(peerUserId)
    val sigMap = Arguments.createMap().apply {
      putString("version", req.signature.version)
      putString("userId", req.signature.userId)
      putString("timestampMs", req.signature.timestampMs)
      putString("nonceBase64url", req.signature.nonceBase64url)
      putString("signatureBase64url", req.signature.signatureBase64url)
    }
    try {
      val bodyBase64 = android.util.Base64.encodeToString(req.body, android.util.Base64.NO_WRAP)
      Arguments.createMap().apply {
        putString("method", req.method)
        putString("target", req.requestTarget)
        putString("bodyBase64", bodyBase64)
        putMap("signature", sigMap)
      }
    } finally {
      req.body.fill(0)
    }
  }

  @ReactMethod
  fun parseContactSearchResponse(responseBase64: String, promise: Promise) = onRuntime(promise) {
    val responseBytes = android.util.Base64.decode(responseBase64, android.util.Base64.DEFAULT)
    try {
      val res = runtime.parseContactSearchResponse(responseBytes)
      Arguments.createMap().apply {
        putString("userId", res.userId)
        putString("username", res.username)
      }
    } finally {
      responseBytes.fill(0)
    }
  }

  @ReactMethod
  fun parseCreateDirectResponse(responseBase64: String, promise: Promise) = onRuntime(promise) {
    val responseBytes = android.util.Base64.decode(responseBase64, android.util.Base64.DEFAULT)
    try {
      val conversationId = runtime.completeCreateDirectResponse(responseBytes)
      Arguments.createMap().apply {
        putString("conversationId", conversationId)
      }
    } finally {
      responseBytes.fill(0)
    }
  }

  /** Required by React Native's NativeEventEmitter contract. */
  @ReactMethod
  fun addListener(eventName: String) {
    if (eventName == EVENT_STATE_CHANGED) listenerCount.incrementAndGet()
  }

  /** Required by React Native's NativeEventEmitter contract. */
  @ReactMethod
  fun removeListeners(count: Double) {
    if (!count.isFinite() || count <= 0) return
    listenerCount.updateAndGet { current -> (current - count.toInt()).coerceAtLeast(0) }
  }

  private fun onRuntime(promise: Promise, operation: () -> Any?) {
    runtime.execute {
      try {
        promise.resolve(operation())
      } catch (error: VeilMobileRuntimeException) {
        promise.rejectRuntimeFailure(error.code)
      } catch (_: Throwable) {
        promise.rejectRuntimeFailure("E_VEIL_RUNTIME")
      }
    }
  }

  private fun onRuntimePublication(promise: Promise, operation: () -> Unit) {
    runtime.execute {
      try {
        operation()
      } catch (error: Throwable) {
        promise.rejectRuntimePublicationFailure(error)
      }
    }
  }

  companion object {
    const val EVENT_STATE_CHANGED = "VeilRuntimeStateChanged"
  }
}

internal fun Promise.publishDirectSessionResult(
  result: NativeDirectSessionActionResult,
  userInfoFactory: () -> WritableMap = { Arguments.createMap() },
) {
  when (result) {
    is NativeDirectSessionActionResult.Success -> resolve(result.install.toWritableMap())
    NativeDirectSessionActionResult.Unavailable ->
      rejectRuntimeFailure(DIRECT_SESSION_ERROR_CODE, userInfoFactory)
  }
}

internal fun Promise.publishDirectTextSendResult(
  result: NativeDirectTextSendResult,
  userInfoFactory: () -> WritableMap = { Arguments.createMap() },
) {
  when (result) {
    NativeDirectTextSendResult.ACCEPTED -> resolve(null)
    NativeDirectTextSendResult.REJECTED ->
      rejectRuntimeFailure(DIRECT_SEND_REJECTED_CODE, userInfoFactory)
    NativeDirectTextSendResult.UNAVAILABLE ->
      rejectRuntimeFailure(DIRECT_SEND_UNAVAILABLE_CODE, userInfoFactory)
  }
}

internal fun Promise.rejectRuntimePublicationFailure(
  error: Throwable,
  userInfoFactory: () -> WritableMap = { Arguments.createMap() },
) {
  val internalCode = if (error is VeilMobileRuntimeException) {
    error.code
  } else {
    "E_VEIL_RUNTIME"
  }
  rejectRuntimeFailure(internalCode, userInfoFactory)
}

/**
 * Publish one closed, typed failure envelope. The factory seam exists only so
 * JVM tests can use React Native's Java-only map without loading JNI.
 */
private fun Promise.rejectRuntimeFailure(
  internalCode: String,
  userInfoFactory: () -> WritableMap = { Arguments.createMap() },
) {
  val failure = runtimeFailureBridgeV1(internalCode)
  val userInfo = userInfoFactory().apply {
    putString(
      PUBLIC_FAILURE_CODE_KEY,
      failure.publicCode.wireValue,
    )
  }
  // Throwable/native/server text must not cross the React Native boundary.
  reject(failure.internalCode, RUNTIME_FAILURE_MESSAGE, userInfo)
}

internal data class PublicDirectConversationView(
  val conversationId: String,
  val name: String,
  val peerUserId: String,
  val peerUsername: String,
) {
  override fun toString(): String = "PublicDirectConversationView(metadata=[REDACTED])"
}

internal data class PublicDirectDirectoryPublication(
  val ready: Boolean,
  val conversations: List<PublicDirectConversationView>,
) {
  override fun toString(): String =
    "PublicDirectDirectoryPublication(ready=$ready, conversations=${conversations.size})"
}

/**
 * Collapse the complete authenticated directory to the public RN projection.
 *
 * The projection is all-or-nothing. A malformed native row, duplicate ID, or
 * lifecycle disagreement must never leave JavaScript with a partial directory
 * that it could continue rendering after the native authority was revoked.
 */
internal fun VeilMobileRuntimeSnapshot.toPublicDirectDirectoryPublication():
  PublicDirectDirectoryPublication {
  val currentBinding = binding
  val bindingIsCurrent = currentBinding?.let { current ->
    isCanonicalNonNilUuid(current.userId) && runCatching {
      CanonicalServerOrigin.parse(current.canonicalServerOrigin).value ==
        current.canonicalServerOrigin
    }.getOrDefault(false)
  } == true
  val hasPublishAuthority = publicFailureCodeV1 == null &&
    identityExists &&
    runtimeRevision in 1L..MAX_PUBLIC_SNAPSHOT_REVISION &&
    directGeneration?.let { it in 1L..MAX_PUBLIC_SNAPSHOT_REVISION } == true &&
    directContentRevision?.let { it in 0L..MAX_PUBLIC_SNAPSHOT_REVISION } == true &&
    sessionState == NativeSessionState.OPEN &&
    connectionState == NativeConnectionState.CONNECTED &&
    directoryReady &&
    secureSyncState == NativeSecureSyncState.HISTORY_SYNCHRONIZED &&
    ownPreKeyState == NativeOwnPreKeyState.PUBLISHED &&
    directDirectoryState == NativeDirectDirectoryState.SYNCHRONIZED &&
    directHistoryState == NativeDirectHistoryState.SYNCHRONIZED &&
    bindingIsCurrent
  if (!hasPublishAuthority) return PublicDirectDirectoryPublication(false, emptyList())

  val publicRows = directConversations.toPublicDirectConversationViewsOrNull(
    checkNotNull(currentBinding).userId,
  )
    ?: return PublicDirectDirectoryPublication(false, emptyList())
  return PublicDirectDirectoryPublication(true, publicRows)
}

private fun List<NativeDirectConversationInstall>.toPublicDirectConversationViewsOrNull(
  authenticatedUserId: String,
): List<PublicDirectConversationView>? {
  if (size > MAX_PUBLIC_DIRECT_CONVERSATIONS) return null
  val output = ArrayList<PublicDirectConversationView>(size)
  var previousConversationId: String? = null
  for (conversation in this) {
    if (
      !isCanonicalNonNilUuid(conversation.conversationId) ||
      previousConversationId?.let { previous -> previous >= conversation.conversationId } == true ||
      !isCanonicalNonNilUuid(conversation.peerUserId) ||
      conversation.peerUserId == authenticatedUserId ||
      !conversation.name.isSafePublicDirectoryText(MAX_PUBLIC_DIRECT_NAME_BYTES) ||
      !conversation.peerUsername.isSafePublicDirectoryText(MAX_PUBLIC_DIRECT_USERNAME_BYTES)
    ) return null
    output += PublicDirectConversationView(
      conversationId = conversation.conversationId,
      name = conversation.name,
      peerUserId = conversation.peerUserId,
      peerUsername = conversation.peerUsername,
    )
    previousConversationId = conversation.conversationId
  }
  return output
}

private fun isCanonicalNonNilUuid(value: String): Boolean = try {
  val parsed = UUID.fromString(value)
  parsed.toString() == value &&
    (parsed.mostSignificantBits != 0L || parsed.leastSignificantBits != 0L)
} catch (_: IllegalArgumentException) {
  false
}

private fun String.isSafePublicDirectoryText(maxBytes: Int): Boolean {
  if (isEmpty()) return false
  var utf8Bytes = 0
  var index = 0
  while (index < length) {
    val first = this[index]
    val codePoint: Int
    val additionalBytes: Int
    when {
      first.code <= 0x7f -> {
        codePoint = first.code
        additionalBytes = 1
      }
      first.code <= 0x7ff -> {
        codePoint = first.code
        additionalBytes = 2
      }
      Character.isHighSurrogate(first) -> {
        if (index + 1 >= length || !Character.isLowSurrogate(this[index + 1])) return false
        codePoint = Character.toCodePoint(first, this[index + 1])
        additionalBytes = 4
        index += 1
      }
      Character.isLowSurrogate(first) -> return false
      else -> {
        codePoint = first.code
        additionalBytes = 3
      }
    }
    if (Character.getType(codePoint) == Character.CONTROL.toInt()) return false
    if (utf8Bytes > maxBytes - additionalBytes) return false
    utf8Bytes += additionalBytes
    index += 1
  }
  return true
}

internal fun VeilMobileRuntimeSnapshot.publicFailureCodeV1WireValue(): String? =
  publicFailureCodeV1?.wireValue

private fun VeilMobileRuntimeSnapshot.toWritableMap(): WritableMap = Arguments.createMap().apply {
  val publicDirectory = toPublicDirectDirectoryPublication()
  putBoolean("identityExists", identityExists)
  putDouble("runtimeRevision", runtimeRevision.toDouble())
  directGeneration?.let { putDouble("directGeneration", it.toDouble()) }
    ?: putNull("directGeneration")
  directContentRevision?.let { putDouble("directContentRevision", it.toDouble()) }
    ?: putNull("directContentRevision")
  putString("sessionState", sessionState.name.lowercase())
  putString("connectionState", connectionState.name.lowercase())
  publicFailureCodeV1WireValue()?.let { wireValue ->
    putString(RUNTIME_SNAPSHOT_PUBLIC_FAILURE_CODE_KEY, wireValue)
  } ?: putNull(RUNTIME_SNAPSHOT_PUBLIC_FAILURE_CODE_KEY)
  putBoolean("directoryReady", publicDirectory.ready)
  putString("secureSyncState", secureSyncState.name.lowercase())
  putMap("binding", binding?.toWritableMap())
  putMap("pendingAccessPass", pendingAccessPass?.toWritableMap())
  putArray("directConversations", Arguments.createArray().also { output ->
    publicDirectory.conversations.forEach { conversation ->
      output.pushMap(conversation.toWritableMap())
    }
  })
}

private const val RUNTIME_SNAPSHOT_PUBLIC_FAILURE_CODE_KEY = "publicFailureCodeV1"

private fun PublicDirectConversationView.toWritableMap(): WritableMap = Arguments.createMap().apply {
  putString("conversationId", conversationId)
  putString("name", name)
  putString("peerUserId", peerUserId)
  putString("peerUsername", peerUsername)
}

private fun PublicAuthenticatedBinding.toWritableMap(): WritableMap = Arguments.createMap().apply {
  putString("canonicalServerOrigin", canonicalServerOrigin)
  putString("userId", userId)
}

private fun PendingNodeAccessPassView.toWritableMap(): WritableMap = Arguments.createMap().apply {
  putString("flowId", flowId)
  putString("canonicalOrigin", canonicalOrigin)
  putString("tokenRef", tokenRef)
  putDouble("expiresInSeconds", expiresInSeconds.toDouble())
}

private fun NativeDirectMessageProjection.toWritableMap(): WritableMap = Arguments.createMap().apply {
  putString("availability", availability.name.lowercase())
  putArray("messages", Arguments.createArray().also { output ->
    messages.forEach { message -> output.pushMap(message.toWritableMap()) }
  })
}

private fun NativeDirectMessageView.toWritableMap(): WritableMap = Arguments.createMap().apply {
  putString("messageId", messageId)
  putString("text", text)
  timestampMs?.let { putDouble("timestampMs", it.toDouble()) } ?: putNull("timestampMs")
  putString("direction", direction.name.lowercase())
  putString("delivery", delivery.name.lowercase())
}

private fun NativeDirectIdentityVerification.toWritableMap(): WritableMap =
  Arguments.createMap().apply {
    putString("canonicalServerOrigin", canonicalServerOrigin)
    putString("peerUserId", peerUserId)
    putString("fingerprintVersion", fingerprintVersion)
    putString("fingerprintEmoji", fingerprintEmoji)
    putString("fingerprintHex", fingerprintHex)
    putString("qrPayload", qrPayload)
    putString(
      "state",
      when (state) {
        NativeDirectIdentityVerificationState.NOT_COMPARED -> "not_compared"
        NativeDirectIdentityVerificationState.VERIFIED_ON_THIS_DEVICE ->
          "verified_on_this_device"
        NativeDirectIdentityVerificationState.IDENTITY_CHANGED -> "identity_changed"
      },
    )
  }

private fun NativeDirectPreKeyInstall.toWritableMap(): WritableMap = Arguments.createMap().apply {
  putString(
    "status",
    when (status) {
      NativeDirectPreKeyInstallStatus.ESTABLISHED -> "established"
      NativeDirectPreKeyInstallStatus.ALREADY_ESTABLISHED -> "already_established"
    },
  )
}

internal fun Double.toSafeDirectGenerationOrNull(): Long? {
  if (
    !isFinite() ||
    this < 1.0 ||
    this > MAX_PUBLIC_SNAPSHOT_REVISION.toDouble() ||
    this != kotlin.math.floor(this)
  ) return null
  return toLong()
}

private const val MAX_PUBLIC_DIRECT_CONVERSATIONS = 10_000
private const val MAX_PUBLIC_DIRECT_NAME_BYTES = 256
private const val MAX_PUBLIC_DIRECT_USERNAME_BYTES = 128
private const val MAX_PUBLIC_SNAPSHOT_REVISION = 9_007_199_254_740_991L
