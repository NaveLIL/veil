package io.veil.mobile.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CanonicalServerOriginTest {
  @Test
  fun canonicalizesSecureOriginAndDerivesExactWebSocketEndpoint() {
    val origin = CanonicalServerOrigin.parse("https://CHAT.Example")

    assertEquals("https://chat.example:443", origin.value)
    assertEquals("wss://chat.example:443/v3/events", origin.websocketUrl)
  }

  @Test
  fun canonicalizesIpv6WithoutResolvingDns() {
    val origin = CanonicalServerOrigin.parse("https://[2001:db8:0:0:0:0:0:1]")

    assertEquals("https://[2001:db8::1]:443", origin.value)
    assertEquals("wss://[2001:db8::1]:443/v3/events", origin.websocketUrl)
  }

  @Test
  fun allowsOnlyExactLoopbackForPlaintextDevelopment() {
    assertEquals(
      "http://127.0.0.1:9080",
      CanonicalServerOrigin.parse("http://127.0.0.1:9080").value,
    )
    for (origin in listOf("http://example.test", "http://127.0.0.2", "ftp://example.test")) {
      assertThrows(IllegalArgumentException::class.java) { CanonicalServerOrigin.parse(origin) }
    }
  }

  @Test
  fun rejectsOriginConfusionInputs() {
    for (origin in listOf(
      "https://user@example.test",
      "https://example.test/path",
      "https://example.test?next=evil",
      "https://example.test#fragment",
      " https://example.test",
      "https://example.test.",
    )) {
      assertThrows(IllegalArgumentException::class.java) { CanonicalServerOrigin.parse(origin) }
    }
  }
}
