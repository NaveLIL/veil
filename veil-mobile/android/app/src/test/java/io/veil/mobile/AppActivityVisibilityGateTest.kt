package io.veil.mobile

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AppActivityVisibilityGateTest {
  @Test
  fun internalActivityHandoffNeverPublishesAStaleBackgroundTransition() {
    val foregrounds = AtomicInteger(0)
    val backgrounds = AtomicInteger(0)
    val scheduled = AtomicReference<Runnable?>()
    val gate = gate(foregrounds, backgrounds, scheduled)

    gate.onActivityStarted()
    gate.onActivityStopped()
    val staleBackground = checkNotNull(scheduled.get())

    gate.onActivityStarted()
    staleBackground.run()

    assertEquals(2, foregrounds.get())
    assertEquals(0, backgrounds.get())
    assertNull(scheduled.get())
  }

  @Test
  fun overlappingMainAndRecoveryActivitiesLockOnlyAfterBothStop() {
    val foregrounds = AtomicInteger(0)
    val backgrounds = AtomicInteger(0)
    val scheduled = AtomicReference<Runnable?>()
    val gate = gate(foregrounds, backgrounds, scheduled)

    gate.onActivityStarted()
    gate.onActivityStarted()
    gate.onActivityStopped()
    assertNull(scheduled.get())

    gate.onActivityStopped()
    checkNotNull(scheduled.getAndSet(null)).run()

    assertEquals(1, foregrounds.get())
    assertEquals(1, backgrounds.get())
  }

  @Test
  fun aRealBackgroundTransitionLocksOnThePostedMainLoopTurn() {
    val foregrounds = AtomicInteger(0)
    val backgrounds = AtomicInteger(0)
    val scheduled = AtomicReference<Runnable?>()
    val gate = gate(foregrounds, backgrounds, scheduled)

    gate.onActivityStarted()
    gate.onActivityStopped()
    assertEquals(0, backgrounds.get())

    checkNotNull(scheduled.getAndSet(null)).run()

    assertEquals(1, foregrounds.get())
    assertEquals(1, backgrounds.get())
  }

  @Test
  fun foregroundEnrollmentIntentCrossesBarrierAndRelocksIfActivityNeverStarts() {
    val foregrounds = AtomicInteger(0)
    val backgrounds = AtomicInteger(0)
    val scheduled = AtomicReference<Runnable?>()
    val gate = gate(foregrounds, backgrounds, scheduled)

    gate.onForegroundIntent()

    assertEquals(1, foregrounds.get())
    assertEquals(0, backgrounds.get())
    checkNotNull(scheduled.get()).run()
    assertEquals(1, backgrounds.get())
  }

  @Test
  fun startedActivityCancelsEnrollmentIntentBackgroundRecheck() {
    val foregrounds = AtomicInteger(0)
    val backgrounds = AtomicInteger(0)
    val scheduled = AtomicReference<Runnable?>()
    val gate = gate(foregrounds, backgrounds, scheduled)

    gate.onForegroundIntent()
    val staleBackground = checkNotNull(scheduled.get())
    gate.onActivityStarted()
    staleBackground.run()

    assertEquals(2, foregrounds.get())
    assertEquals(0, backgrounds.get())
    assertNull(scheduled.get())
  }

  @Test
  fun configurationRecreationDoesNotPublishAFalseBackground() {
    val foregrounds = AtomicInteger(0)
    val backgrounds = AtomicInteger(0)
    val scheduled = AtomicReference<Runnable?>()
    val gate = gate(foregrounds, backgrounds, scheduled)

    gate.onActivityStarted()
    gate.onActivityStopped(isChangingConfigurations = true)
    gate.onActivityStarted()

    assertEquals(2, foregrounds.get())
    assertEquals(0, backgrounds.get())
    assertNull(scheduled.get())
  }

  @Test
  fun untrustedDependencyActivityCannotGrantOrRetainForegroundAuthority() {
    val foregrounds = AtomicInteger(0)
    val backgrounds = AtomicInteger(0)
    val scheduled = AtomicReference<Runnable?>()
    val gate = gate(foregrounds, backgrounds, scheduled)

    gate.onActivityStarted(isTrustedSurface = false)
    gate.onActivityStopped(isTrustedSurface = false)

    assertEquals(0, foregrounds.get())
    assertEquals(0, backgrounds.get())
    assertNull(scheduled.get())

    gate.onActivityStarted()
    gate.onActivityStopped()
    gate.onActivityStarted(isTrustedSurface = false)
    checkNotNull(scheduled.get()).run()

    assertEquals(1, foregrounds.get())
    assertEquals(1, backgrounds.get())
  }

  private fun gate(
    foregrounds: AtomicInteger,
    backgrounds: AtomicInteger,
    scheduled: AtomicReference<Runnable?>,
  ) = AppActivityVisibilityGate(
    scheduleBackground = { operation -> scheduled.set(operation) },
    cancelBackground = { operation -> scheduled.compareAndSet(operation, null) },
    onForeground = { foregrounds.incrementAndGet() },
    onBackground = { backgrounds.incrementAndGet() },
  )
}
