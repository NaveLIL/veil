package io.veil.mobile.crypto

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class SerializedIdentityStateTest {
  @Test
  fun closeWaitsForTheActiveNativeOperation() {
    val identity = BlockingIdentity()
    val state = SerializedIdentityState { identity }
    val operationFinished = CountDownLatch(1)
    val closeAttempted = CountDownLatch(1)
    val closeFinished = CountDownLatch(1)

    val operationThread = thread(name = "identity-operation") {
      state.withExisting { active -> active.blockingOperation() }
      operationFinished.countDown()
    }
    assertTrue(identity.operationStarted.await(5, TimeUnit.SECONDS))

    val closeThread = thread(name = "identity-close") {
      closeAttempted.countDown()
      state.close()
      closeFinished.countDown()
    }
    assertTrue(closeAttempted.await(5, TimeUnit.SECONDS))
    assertFalse(identity.closed.get())

    identity.releaseOperation.countDown()
    assertTrue(operationFinished.await(5, TimeUnit.SECONDS))
    assertTrue(closeFinished.await(5, TimeUnit.SECONDS))
    operationThread.join()
    closeThread.join()
    assertTrue(identity.closed.get())
    assertFalse(identity.closedDuringOperation.get())
  }

  @Test
  fun closeIsIdempotentAndPermanentlyRejectsFurtherUse() {
    val first = BlockingIdentity()
    val second = BlockingIdentity()
    val identities = ArrayDeque(listOf(first, second))
    val state = SerializedIdentityState { identities.removeFirstOrNull() }

    state.withExisting { assertSame(first, it) }
    state.close()
    state.close()
    assertEquals(1, first.closeCount)
    org.junit.Assert.assertThrows(IdentityAccessSuspendedException::class.java) {
      state.withExisting { error("destroyed owner must not reload") }
    }
    assertEquals(0, second.closeCount)
  }

  @Test
  fun suspendedOwnerRejectsBridgeUseWithoutReloadingUntilResume() {
    val first = BlockingIdentity()
    val second = BlockingIdentity()
    val identities = ArrayDeque(listOf(first, second))
    var loads = 0
    val state = SerializedIdentityState {
      loads += 1
      identities.removeFirstOrNull()
    }

    state.withExisting { assertSame(first, it) }
    assertEquals(1, loads)
    state.suspendAccess()
    assertTrue(first.closed.get())

    org.junit.Assert.assertThrows(IdentityAccessSuspendedException::class.java) {
      state.withExisting { error("must not reload while backgrounded") }
    }
    assertEquals(1, loads)

    state.resumeAccess()
    state.withExisting { assertSame(second, it) }
    assertEquals(2, loads)
    state.close()
  }

  @Test
  fun backgroundEpochRejectsAnExpensiveResultWithoutBlockingSuspend() {
    val state = SerializedIdentityState<BlockingIdentity> { null }
    val operationStarted = CountDownLatch(1)
    val releaseOperation = CountDownLatch(1)
    val finished = CountDownLatch(1)
    val published = AtomicBoolean(false)
    val rejected = AtomicBoolean(false)

    val worker = thread(name = "identity-expensive-operation") {
      try {
        state.runIfAccessible(
          operation = {
            operationStarted.countDown()
            check(releaseOperation.await(5, TimeUnit.SECONDS)) { "operation timed out" }
            "recovery material"
          },
          publish = { published.set(true) },
        )
      } catch (_: IdentityAccessSuspendedException) {
        rejected.set(true)
      } finally {
        finished.countDown()
      }
    }
    assertTrue(operationStarted.await(5, TimeUnit.SECONDS))

    // suspendAccess must not wait for the expensive non-handle operation.
    state.suspendAccess()
    assertFalse(published.get())
    releaseOperation.countDown()

    assertTrue(finished.await(5, TimeUnit.SECONDS))
    worker.join()
    assertTrue(rejected.get())
    assertFalse(published.get())
  }

  private class BlockingIdentity : AutoCloseable {
    val operationStarted = CountDownLatch(1)
    val releaseOperation = CountDownLatch(1)
    val closed = AtomicBoolean(false)
    val closedDuringOperation = AtomicBoolean(false)
    private val inOperation = AtomicBoolean(false)
    var closeCount = 0

    fun blockingOperation() {
      inOperation.set(true)
      operationStarted.countDown()
      check(releaseOperation.await(5, TimeUnit.SECONDS)) { "test operation timed out" }
      inOperation.set(false)
    }

    override fun close() {
      closeCount += 1
      closedDuringOperation.set(inOperation.get())
      closed.set(true)
    }
  }
}
