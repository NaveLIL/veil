package io.veil.mobile.crypto

/**
 * Owns one closeable native identity and serializes every operation with close.
 *
 * Callers never receive the handle outside the scoped callbacks, so lifecycle
 * teardown cannot close a UniFFI object while one of its methods is running.
 */
internal class SerializedIdentityState<T : AutoCloseable>(
  initiallyAccessible: Boolean = true,
  private val loadExisting: () -> T?,
) : AutoCloseable {
  private val lock = Any()
  private var active: T? = null
  private var accessAllowed = initiallyAccessible
  private var destroyed = false
  private var accessEpoch = 0L

  /**
   * Runs expensive non-handle work without blocking lifecycle teardown, then
   * publishes its result only if the exact foreground epoch is still current.
   */
  fun <R> runIfAccessible(operation: () -> R, publish: (R) -> Unit) {
    val epoch = synchronized(lock) {
      requireAccessLocked()
      accessEpoch
    }
    val result = operation()
    synchronized(lock) {
      requireAccessLocked()
      if (accessEpoch != epoch) throw IdentityAccessSuspendedException()
      publish(result)
    }
  }

  fun <R> withExisting(operation: (T) -> R): R? = synchronized(lock) {
    requireAccessLocked()
    val identity = active ?: loadExisting()?.also { active = it }
    identity?.let(operation)
  }

  /**
   * Installs [candidate] only when no persisted or loaded identity exists.
   *
   * [verifyExisting] and [persistCandidate] both run inside the same critical
   * section as lifecycle close. Ownership transfers to this state only when
   * the method returns `true`.
   */
  fun installOrVerify(
    candidate: T,
    verifyExisting: (existing: T, candidate: T) -> Unit,
    persistCandidate: () -> Unit,
  ): Boolean = synchronized(lock) {
    requireAccessLocked()
    val existing = active ?: loadExisting()?.also { active = it }
    if (existing != null) {
      verifyExisting(existing, candidate)
      return@synchronized false
    }

    persistCandidate()
    active = candidate
    true
  }

  fun suspendAccess() {
    synchronized(lock) {
      accessEpoch += 1
      accessAllowed = false
      closeActiveLocked()
    }
  }

  fun resumeAccess() {
    synchronized(lock) {
      if (!destroyed && !accessAllowed) {
        accessEpoch += 1
        accessAllowed = true
      }
    }
  }

  override fun close() {
    synchronized(lock) {
      accessEpoch += 1
      destroyed = true
      accessAllowed = false
      closeActiveLocked()
    }
  }

  private fun requireAccessLocked() {
    if (!accessAllowed || destroyed) throw IdentityAccessSuspendedException()
  }

  private fun closeActiveLocked() {
    val closing = active
    active = null
    closing?.close()
  }
}

internal class IdentityAccessSuspendedException :
  IllegalStateException("native identity access is suspended")
