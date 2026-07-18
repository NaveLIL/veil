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
    runtime.lockSession().toWritableMap()
  }

  @ReactMethod
  fun cancelPendingAccessPass(flowId: String, promise: Promise) = onRuntime(promise) {
    runtime.cancelPendingAccessPass(flowId)
  }

  @ReactMethod
  fun projectDirectMessages(conversationId: String, promise: Promise) = onRuntimePublication(promise) {
    runtime.publishDirectMessages(conversationId) { projection ->
      promise.resolve(projection.toWritableMap())
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
        promise.reject(error.code, error.message ?: "Native mobile runtime operation failed")
      } catch (_: Throwable) {
        promise.reject("E_VEIL_RUNTIME", "Native mobile runtime operation failed")
      }
    }
  }

  private fun onRuntimePublication(promise: Promise, operation: () -> Unit) {
    runtime.execute {
      try {
        operation()
      } catch (error: VeilMobileRuntimeException) {
        promise.reject(error.code, error.message ?: "Native mobile runtime operation failed")
      } catch (_: Throwable) {
        promise.reject("E_VEIL_RUNTIME", "Native mobile runtime operation failed")
      }
    }
  }

  companion object {
    const val EVENT_STATE_CHANGED = "VeilRuntimeStateChanged"
  }
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
  val hasPublishAuthority = identityExists &&
    runtimeRevision in 1L..MAX_PUBLIC_SNAPSHOT_REVISION &&
    directGeneration?.let { it in 1L..MAX_PUBLIC_SNAPSHOT_REVISION } == true &&
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

private fun VeilMobileRuntimeSnapshot.toWritableMap(): WritableMap = Arguments.createMap().apply {
  val publicDirectory = toPublicDirectDirectoryPublication()
  putBoolean("identityExists", identityExists)
  putDouble("runtimeRevision", runtimeRevision.toDouble())
  directGeneration?.let { putDouble("directGeneration", it.toDouble()) }
    ?: putNull("directGeneration")
  putString("sessionState", sessionState.name.lowercase())
  putString("connectionState", connectionState.name.lowercase())
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

private const val MAX_PUBLIC_DIRECT_CONVERSATIONS = 10_000
private const val MAX_PUBLIC_DIRECT_NAME_BYTES = 256
private const val MAX_PUBLIC_DIRECT_USERNAME_BYTES = 128
private const val MAX_PUBLIC_SNAPSHOT_REVISION = 9_007_199_254_740_991L
