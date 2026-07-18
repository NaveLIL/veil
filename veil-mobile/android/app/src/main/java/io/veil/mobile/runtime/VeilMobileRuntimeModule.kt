package io.veil.mobile.runtime

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule
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

  companion object {
    const val EVENT_STATE_CHANGED = "VeilRuntimeStateChanged"
  }
}

private fun VeilMobileRuntimeSnapshot.toWritableMap(): WritableMap = Arguments.createMap().apply {
  putBoolean("identityExists", identityExists)
  putString("sessionState", sessionState.name.lowercase())
  putString("connectionState", connectionState.name.lowercase())
  putBoolean("directoryReady", directoryReady)
  putString("secureSyncState", secureSyncState.name.lowercase())
  putMap("binding", binding?.toWritableMap())
  putMap("pendingAccessPass", pendingAccessPass?.toWritableMap())
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
