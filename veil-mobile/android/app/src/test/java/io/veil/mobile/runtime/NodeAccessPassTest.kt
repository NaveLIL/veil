package io.veil.mobile.runtime

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NodeAccessPassTest {
  private val tokenBytes = ByteArray(32) { index -> (index + 1).toByte() }
  private val token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes)

  @Test
  fun parsesHttpsAndCustomTransportsIntoOneCanonicalOrigin() {
    val web = NodeAccessPassParser.parse("https://ACCESS.Example/enroll#invite=$token")
    val encodedOrigin = URLEncoder.encode("https://ACCESS.Example", StandardCharsets.UTF_8.name())
    val customQuery = NodeAccessPassParser.parse(
      "veil://enroll/v1?origin=$encodedOrigin&invite=$token",
    )
    val customFragment = NodeAccessPassParser.parse(
      "veil://enroll/v1?origin=$encodedOrigin#invite=$token",
    )

    web.use {
      customQuery.use {
        customFragment.use {
          assertEquals("https://access.example:443", web.canonicalOrigin)
          assertEquals(web.canonicalOrigin, customQuery.canonicalOrigin)
          assertEquals(web.canonicalOrigin, customFragment.canonicalOrigin)
          assertArrayEquals(tokenBytes, web.token)
          assertArrayEquals(tokenBytes, customQuery.token)
          assertArrayEquals(tokenBytes, customFragment.token)
          assertFalse(web.toString().contains(token))
        }
      }
    }
  }

  @Test
  fun rejectsMalformedAmbiguousAndLeakProneLinks() {
    val encodedOrigin = URLEncoder.encode("https://access.example", StandardCharsets.UTF_8.name())
    val invalid = listOf(
      "http://access.example/enroll#invite=$token",
      "https://user@access.example/enroll#invite=$token",
      "https://access.example/enroll/#invite=$token",
      "https://access.example/%65nroll#invite=$token",
      "https://access.example/enroll?next=evil#invite=$token",
      "https://access.example/enroll#invite=short",
      "https://access.example/enroll#invite=$token&extra=1",
      "veil://enroll/v2?origin=$encodedOrigin&invite=$token",
      "veil://enroll/v1?origin=${URLEncoder.encode("http://access.example", "UTF-8")}&invite=$token",
      "veil://enroll/v1?origin=$encodedOrigin&unknown=x&invite=$token",
      "veil://enroll/v1?origin=$encodedOrigin&origin=$encodedOrigin&invite=$token",
      "veil://enroll/v1?origin=$encodedOrigin&invite=$token#invite=$token",
      "veil://enroll/v1?origin=$encodedOrigin&invite=${token}=",
      "veil://enroll/v1?origin=$encodedOrigin&invite=$token&",
    )

    invalid.forEach { raw ->
      assertThrows(raw, IllegalArgumentException::class.java) { NodeAccessPassParser.parse(raw) }
    }
  }

  @Test
  fun rejectsNonCanonicalBase64UrlTrailingBits() {
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    val finalIndex = alphabet.indexOf(token.last())
    assertEquals(0, finalIndex and 0x03)
    val nonCanonical = token.dropLast(1) + alphabet[finalIndex + 1]

    assertThrows(IllegalArgumentException::class.java) {
      NodeAccessPassParser.parse("https://access.example/enroll#invite=$nonCanonical")
    }
  }

  @Test
  fun recognizesMalformedEnrollmentTargetsSoTheyCannotFallThroughToReactNativeLinking() {
    assertTrue(NodeAccessPassParser.isPotentialEnrollment("veil://enroll/%"))
    assertTrue(NodeAccessPassParser.isPotentialEnrollment("https://veil.erez.pro/enroll#%"))
    assertTrue(NodeAccessPassParser.isPotentialEnrollment("https://veil.erez.pro:443/enroll#%"))
    assertTrue(NodeAccessPassParser.isPotentialEnrollment("https://user@veil.erez.pro/enroll#%"))
    assertTrue(NodeAccessPassParser.isPotentialEnrollment("HTTPS://VEIL.EREZ.PRO/enroll?%"))
    assertFalse(NodeAccessPassParser.isPotentialEnrollment("https://veil.erez.pro.evil/enroll#%"))
    assertFalse(NodeAccessPassParser.isPotentialEnrollment("https://veil.erez.pro/other#%"))
  }

  @Test
  fun storeExpiresCancelsAndNeverReturnsBearerInItsView() {
    var now = 1_000L
    var randomValue = 0
    val store = NodeAccessPassStore(
      clockMillis = { now },
      randomBytes = { output -> output.fill((++randomValue).toByte()) },
      ttlMillis = 10_000L,
    )

    val first = store.stage("https://access.example/enroll#invite=$token")
    assertEquals("https://access.example:443", first.canonicalOrigin)
    assertEquals(12, first.tokenRef.length)
    assertFalse(first.toString().contains(token))
    assertNotNull(store.attempt(first.flowId, first.canonicalOrigin)?.also { attempt ->
      assertArrayEquals(tokenBytes, attempt.token)
      attempt.close()
      assertTrue(attempt.token.all { it == 0.toByte() })
    })

    assertFalse(store.cancel("00".repeat(32)))
    assertTrue(store.cancel(first.flowId))
    assertNull(store.snapshot())

    val expiring = store.stage("https://access.example/enroll#invite=$token")
    now += 10_001L
    assertNull(store.snapshot())
    assertNull(store.attempt(expiring.flowId, expiring.canonicalOrigin))
  }

  @Test
  fun staleSuccessCannotClearAReplacementPass() {
    var randomValue = 0
    val store = NodeAccessPassStore(
      clockMillis = { 1_000L },
      randomBytes = { output -> output.fill((++randomValue).toByte()) },
    )
    val first = store.stage("https://access.example/enroll#invite=$token")
    val attempt = store.attempt(first.flowId, first.canonicalOrigin)!!
    val second = store.stage("https://other.example/enroll#invite=$token")

    assertNotEquals(first.flowId, second.flowId)
    store.clearAfterSuccess(attempt.flowId)
    assertEquals(second.flowId, store.snapshot()?.flowId)
    attempt.close()
  }

  @Test
  fun invalidReplacementDoesNotDestroyAValidPendingPass() {
    val store = NodeAccessPassStore(randomBytes = { output -> output.fill(7) })
    val valid = store.stage("https://access.example/enroll#invite=$token")

    assertThrows(IllegalArgumentException::class.java) {
      store.stage("https://access.example/enroll#invite=short")
    }
    assertEquals(valid.flowId, store.snapshot()?.flowId)
  }
}
