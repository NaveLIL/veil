package io.veil.mobile.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class NativeContactBridgeAuthorityTest {
  @Test
  fun queuedSearchThenBridgeInvalidationCannotCreateANativeHttpFlow() {
    val authority = NativeContactBridgeAuthority()
    val queued = ArrayDeque<() -> Unit>()
    var startedHttp = 0
    var rejected = 0
    var cancelled = 0
    queued.add {
      authority.runIfOpen({ startedHttp += 1 }, { rejected += 1 })
    }
    authority.close { cancelled += 1 }
    queued.removeFirst().invoke()
    assertEquals(0, startedHttp)
    assertEquals(1, rejected)
    assertEquals(1, cancelled)
    assertFalse(authority.isOpen())
  }

  @Test
  fun cancellationCompletesOutsideTheBridgeGateAndCannotReopenAuthority() {
    val authority = NativeContactBridgeAuthority()
    var invoked = 0
    var rejected = 0
    authority.close {
      authority.runIfOpen({ invoked += 1 }, { rejected += 1 })
    }
    authority.runIfOpen({ invoked += 1 }, { rejected += 1 })
    assertEquals(0, invoked)
    assertEquals(2, rejected)
  }
}
