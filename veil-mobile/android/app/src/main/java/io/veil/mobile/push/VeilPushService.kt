package io.veil.mobile.push

import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/**
 * UnifiedPush is only a generic wake-up signal. It never supplies trusted routing,
 * sender, conversation, or message data to the UI or cryptographic state machine.
 */
class VeilPushService : PushService() {
  override fun onMessage(message: PushMessage, instance: String) {
    if (!validInstance(instance) || !message.decrypted || message.content.size != EXPECTED_WAKE_BYTES) return
    // The authenticated native sync runtime will consume this wake signal once its
    // account/origin-bound session is ready. Until then, fail closed and discard it.
    VeilPushWakeCoordinator.requestBoundedSync(applicationContext, instance)
    
    androidx.core.content.ContextCompat.startForegroundService(
      applicationContext,
      android.content.Intent(applicationContext, io.veil.mobile.runtime.VeilEventsService::class.java).apply {
        action = "io.veil.mobile.ACTION_FORCE_RECONNECT"
      }
    )
  }

  override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
    if (!validInstance(instance)) return
    // Endpoint publication requires an authenticated, account/origin-bound native
    // session. Never expose endpoint keys to JavaScript or persist them ad hoc here.
    VeilPushWakeCoordinator.publishEndpointWhenAuthenticated(applicationContext, instance, endpoint)
  }

  override fun onRegistrationFailed(reason: FailedReason, instance: String) {
    if (validInstance(instance)) VeilPushWakeCoordinator.markUnavailable(applicationContext, instance)
  }

  override fun onUnregistered(instance: String) {
    if (validInstance(instance)) VeilPushWakeCoordinator.markUnavailable(applicationContext, instance)
  }

  private fun validInstance(instance: String): Boolean =
    instance.length in 16..160 && INSTANCE_PATTERN.matches(instance)

  companion object {
    private const val EXPECTED_WAKE_BYTES = 2048
    private val INSTANCE_PATTERN = Regex("^veil:v1:[A-Za-z0-9_-]+$")
  }
}

private object VeilPushWakeCoordinator {
  fun requestBoundedSync(context: android.content.Context, instance: String) {
    // Deliberately dormant until the native authenticated sync runtime lands.
  }

  fun publishEndpointWhenAuthenticated(
    context: android.content.Context,
    instance: String,
    endpoint: PushEndpoint,
  ) {
    // Deliberately dormant: publishing without native account binding would create
    // a cross-account endpoint substitution risk.
  }

  fun markUnavailable(context: android.content.Context, instance: String) {
    // No mutable subscription state is trusted before native session binding.
  }
}
