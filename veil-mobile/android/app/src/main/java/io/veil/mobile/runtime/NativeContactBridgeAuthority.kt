package io.veil.mobile.runtime

/** A discarded React module cannot enqueue a new contact flow in the runtime. */
internal class NativeContactBridgeAuthority {
  private val gate = Any()
  @Volatile private var open = true

  fun runIfOpen(operation: () -> Unit, unavailable: () -> Unit) {
    synchronized(gate) {
      if (open) operation() else unavailable()
    }
  }

  fun isOpen(): Boolean = open

  fun close(cancel: () -> Unit) {
    synchronized(gate) { open = false }
    // Never hold the bridge gate while cancelling the runtime's stateLock:
    // cancellation can synchronously complete an outstanding native callback.
    cancel()
  }
}
