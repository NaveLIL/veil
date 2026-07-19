package io.veil.mobile.crypto

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeIdentityVaultProcessLockTest {
  @Test
  fun overlappingOwnersCannotBothCommitDifferentIdentities() {
    val persisted = AtomicReference<String?>(null)
    val firstEntered = CountDownLatch(1)
    val releaseFirst = CountDownLatch(1)
    val secondAttempted = CountDownLatch(1)
    val secondEnteredTransaction = AtomicBoolean(false)
    val secondCommitted = AtomicBoolean(false)

    val first = thread(name = "identity-owner-a") {
      NativeIdentityVaultProcessLock.withLock {
        firstEntered.countDown()
        check(releaseFirst.await(5, TimeUnit.SECONDS)) { "first vault transaction timed out" }
        if (persisted.get() == null) persisted.set("identity-a")
      }
    }
    assertTrue(firstEntered.await(5, TimeUnit.SECONDS))

    val second = thread(name = "identity-owner-b") {
      secondAttempted.countDown()
      NativeIdentityVaultProcessLock.withLock {
        secondEnteredTransaction.set(true)
        if (persisted.get() == null) {
          persisted.set("identity-b")
          secondCommitted.set(true)
        }
      }
    }
    assertTrue(secondAttempted.await(5, TimeUnit.SECONDS))
    Thread.yield()
    assertFalse(secondEnteredTransaction.get())

    releaseFirst.countDown()
    first.join(5_000)
    second.join(5_000)
    assertFalse(first.isAlive)
    assertFalse(second.isAlive)
    assertEquals("identity-a", persisted.get())
    assertFalse(secondCommitted.get())
  }
}
