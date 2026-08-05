package io.veil.mobile.runtime

import io.veil.mobile.BuildConfig
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import okhttp3.Protocol
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import kotlin.concurrent.thread
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

class NativeDirectHttpTransportTest {
  private lateinit var server: MockWebServer
  private lateinit var transport: NativeDirectHttpTransport
  private lateinit var serverOrigin: String

  @Before
  fun setUp() {
    if (!BuildConfig.DEBUG) return

    val heldCertificate = HeldCertificate.Builder()
      .commonName("localhost")
      .addSubjectAlternativeName("localhost")
      .addSubjectAlternativeName("127.0.0.1")
      .build()
    val serverCertificates = HandshakeCertificates.Builder()
      .heldCertificate(heldCertificate)
      .build()
    val clientCertificates = HandshakeCertificates.Builder()
      .addTrustedCertificate(heldCertificate.certificate)
      .build()

    server = MockWebServer()
    server.useHttps(serverCertificates.sslSocketFactory(), false)
    server.protocols = listOf(Protocol.HTTP_1_1)
    server.start()
    serverOrigin = "https://${server.url("/").host}:${server.port}"
    transport = NativeDirectHttpTransport(
      clientCertificates.sslSocketFactory(),
      clientCertificates.trustManager,
    )
  }

  @After
  fun tearDown() {
    if (::server.isInitialized) server.shutdown()
  }

  @Test
  fun signedGetPreservesExactTargetHostHeadersAndEmptyBodyOnWire() {
    requireDebugTestTlsFixture()
    val responseBody = """{"conversations":[]}""".toByteArray()
    server.enqueue(MockResponse().setResponseCode(200).setBody(Buffer().write(responseBody)))
    val target = "/v1/conversations?limit=100&cursor=z%2B1%2F2&order=first&order=second"

    val result = executeAndAwait(signedRequest(target = target))

    assertArrayEquals(responseBody, result.requireSuccessBody())
    val recorded = server.takeRequest(5, TimeUnit.SECONDS)
      ?: throw AssertionError("signed request did not reach MockWebServer")
    assertEquals("GET", recorded.method)
    assertEquals(target, recorded.path)
    assertEquals(0L, recorded.bodySize)
    assertEquals("${server.url("/").host}:${server.port}", recorded.getHeader("Host"))
    assertEquals("application/json", recorded.getHeader("Accept"))
    assertEquals(REST_AUTH_VERSION, recorded.getHeader("X-Veil-REST-Auth-Version"))
    assertEquals(USER_ID, recorded.getHeader("X-Veil-User"))
    assertEquals(TIMESTAMP_MS, recorded.getHeader("X-Veil-Timestamp"))
    assertEquals(NONCE_BASE64URL, recorded.getHeader("X-Veil-Nonce"))
    assertEquals(SIGNATURE_BASE64URL, recorded.getHeader("X-Veil-Signature"))
    assertNull(recorded.getHeader("X-User-ID"))
    assertNull(recorded.getHeader("Content-Type"))
  }

  @Test
  fun signedOwnPrekeyPostPreservesExactBodyTargetAndHeadersOnWire() {
    requireDebugTestTlsFixture()
    val body = """{"device_id":"00112233445566778899aabbccddeeff","signed_prekey":{"key_id":7}}"""
      .toByteArray()
    val original = body.copyOf()
    server.enqueue(
      MockResponse()
        .setResponseCode(200)
        .setBody("""{"stored":1,"opk_remaining":12}"""),
    )
    val input = signedRequest(
      target = "/v1/prekeys",
      responseLimit = NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES,
      method = NativeDirectHttpMethod.POST,
      body = body,
    )

    val result = executeAndAwait(input)

    assertTrue(result is NativeDirectHttpResult.Success)
    val recorded = server.takeRequest(5, TimeUnit.SECONDS)
      ?: throw AssertionError("signed prekey POST did not reach MockWebServer")
    assertEquals("POST", recorded.method)
    assertEquals("/v1/prekeys", recorded.path)
    assertArrayEquals(original, recorded.body.readByteArray())
    assertEquals("application/json", recorded.getHeader("Content-Type"))
    assertEquals(original.size.toString(), recorded.getHeader("Content-Length"))
    assertEquals("application/json", recorded.getHeader("Accept"))
    assertEquals(REST_AUTH_VERSION, recorded.getHeader("X-Veil-REST-Auth-Version"))
    assertEquals(USER_ID, recorded.getHeader("X-Veil-User"))
    assertEquals(TIMESTAMP_MS, recorded.getHeader("X-Veil-Timestamp"))
    assertEquals(NONCE_BASE64URL, recorded.getHeader("X-Veil-Nonce"))
    assertEquals(SIGNATURE_BASE64URL, recorded.getHeader("X-Veil-Signature"))
    assertFalse(input.toString().contains(String(original)))
    assertFalse(input.toString().contains(SIGNATURE_BASE64URL))
  }

  @Test
  fun preparedOwnPrekeyPostOwnsAnExactBodyCopy() {
    val body = """{"device_id":"00112233445566778899aabbccddeeff"}""".toByteArray()
    val original = body.copyOf()
    val prepared = NativeDirectHttpTransport().prepareRequest(
      signedRequest(
        origin = "https://example.test:443",
        target = "/v1/prekeys",
        responseLimit = NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES,
        method = NativeDirectHttpMethod.POST,
        body = body,
      ),
    )

    body.fill(0)
    val written = Buffer()
    val preparedBody = prepared.body
      ?: throw AssertionError("prepared prekey POST body is absent")
    preparedBody.writeTo(written)

    assertArrayEquals(original, written.readByteArray())
  }

  @Test
  fun preparedRequestUsesOnlyApprovedHeadersAndKeepsDefaultPortInHost() {
    val localTransport = NativeDirectHttpTransport()
    val target = "/v1/prekeys/0123456789abcdef?b=2&a=1"
    val request = signedRequest(
      origin = "https://example.test:443",
      target = target,
      responseLimit = NativeDirectHttpLimits.PREKEY_BYTES,
    )

    val prepared = localTransport.prepareRequest(request)

    assertEquals("GET", prepared.method)
    assertNull(prepared.body)
    assertEquals(target, prepared.url.encodedPath + "?" + prepared.url.encodedQuery)
    assertEquals("example.test:443", prepared.header("Host"))
    assertEquals(
      setOf(
        "Accept",
        "Host",
        "X-Veil-Nonce",
        "X-Veil-REST-Auth-Version",
        "X-Veil-Signature",
        "X-Veil-Timestamp",
        "X-Veil-User",
      ),
      prepared.headers.names(),
    )
  }

  @Test
  fun redirectIsReturnedAsGenericFailureAndNeverFollowed() {
    requireDebugTestTlsFixture()
    server.enqueue(
      MockResponse()
        .setResponseCode(302)
        .setHeader("Location", server.url("/must-not-be-followed")),
    )

    val result = executeAndAwait(signedRequest())

    assertFailure(NativeDirectHttpFailure.UNEXPECTED_STATUS, result)
    assertEquals(1, server.requestCount)
  }

  @Test
  fun peerPreKeyConnectionFailureIsNeverRetried() {
    requireDebugTestTlsFixture()
    server.enqueue(
      MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START),
    )
    // A second response would make an accidental OkHttp retry look successful.
    server.enqueue(MockResponse().setResponseCode(200).setBody("must-not-be-used"))
    val request = signedRequest(
      target = "/v1/prekeys/${"ab".repeat(32)}?transparency_from_size=0",
      responseLimit = NativeDirectHttpLimits.PREKEY_BYTES,
    )

    val result = executeAndAwait(request)

    assertFailure(NativeDirectHttpFailure.NETWORK, result)
    assertEquals(1, server.requestCount)
  }

  @Test
  fun peerPreKeyStatusFollowUpIsBlockedBeforeSecondNetworkExchange() {
    requireDebugTestTlsFixture()
    server.enqueue(
      MockResponse()
        .setResponseCode(503)
        .setHeader("Retry-After", "0"),
    )
    // OkHttp normally follows this exact response immediately. A second
    // response would make the destructive peer-prekey GET appear successful.
    server.enqueue(MockResponse().setResponseCode(200).setBody("must-not-be-used"))
    val request = signedRequest(
      target = "/v1/prekeys/${"ab".repeat(32)}?transparency_from_size=0",
      responseLimit = NativeDirectHttpLimits.PREKEY_BYTES,
    )

    val result = executeAndAwait(request)

    assertFailure(NativeDirectHttpFailure.NETWORK, result)
    assertEquals(1, server.requestCount)
  }

  @Test
  fun non200BodyNeverCrossesTheSanitizedFailureBoundary() {
    requireDebugTestTlsFixture()
    val secretBody = "server-secret-diagnostic-body"
    server.enqueue(MockResponse().setResponseCode(401).setBody(secretBody))

    val result = executeAndAwait(signedRequest())

    assertFailure(NativeDirectHttpFailure.UNEXPECTED_STATUS, result)
    assertFalse(result.toString().contains(secretBody))
  }

  @Test
  fun declaredOversizeIsRejectedBeforeBodyConsumption() {
    requireDebugTestTlsFixture()
    val limit = 32L
    server.enqueue(
      MockResponse()
        .setResponseCode(200)
        .setBody("x")
        .setHeader("Content-Length", limit + 1L),
    )

    val result = executeAndAwait(signedRequest(responseLimit = limit))

    assertFailure(NativeDirectHttpFailure.RESPONSE_TOO_LARGE, result)
  }

  @Test
  fun chunkedOversizeIsDetectedByReadingAtMostLimitPlusOne() {
    requireDebugTestTlsFixture()
    val limit = 1_024L
    val oversized = ByteArray((limit + 1L).toInt()) { 0x5a }
    server.enqueue(
      MockResponse()
        .setResponseCode(200)
        .setChunkedBody(Buffer().write(oversized), 127),
    )

    val result = executeAndAwait(signedRequest(responseLimit = limit))

    assertFailure(NativeDirectHttpFailure.RESPONSE_TOO_LARGE, result)
  }

  @Test
  fun cancellationCompletesOnceWithSanitizedFailureAndHandle() {
    requireDebugTestTlsFixture()
    val target = "/v1/prekeys/peer-identity-key-must-not-leak"
    val signature = SIGNATURE_BASE64URL
    server.enqueue(
      MockResponse()
        .setSocketPolicy(SocketPolicy.NO_RESPONSE),
    )
    val callbackResult = AtomicReference<NativeDirectHttpResult?>()
    val callbackCount = java.util.concurrent.atomic.AtomicInteger(0)
    val completed = CountDownLatch(1)
    val input = signedRequest(target = target)

    val call = transport.createCall(input) { result ->
      callbackCount.incrementAndGet()
      callbackResult.set(result)
      completed.countDown()
    }
    assertTrue(input.toString().let { text ->
      !text.contains(target) && !text.contains(signature) && !text.contains(serverOrigin)
    })
    call.start()
    server.takeRequest(5, TimeUnit.SECONDS)
      ?: throw AssertionError("cancellable request did not reach MockWebServer")
    call.cancel()

    assertTrue("cancelled callback timed out", completed.await(5, TimeUnit.SECONDS))
    assertFailure(
      NativeDirectHttpFailure.CANCELLED,
      callbackResult.get() ?: throw AssertionError("cancelled callback returned no result"),
    )
    assertEquals(1, callbackCount.get())
    assertFalse(call.toString().contains(target))
    assertFalse(call.toString().contains(signature))
  }

  @Test
  fun cancellationBeforeStartNeverReachesNetworkAndStartStaysANoOp() {
    requireDebugTestTlsFixture()
    val callbackResult = AtomicReference<NativeDirectHttpResult?>()
    val callbackCount = AtomicInteger(0)
    val completed = CountDownLatch(1)
    val call = transport.createCall(signedRequest()) { result ->
      callbackCount.incrementAndGet()
      callbackResult.set(result)
      completed.countDown()
    }

    call.cancel()
    call.start()

    assertTrue("cancel-before-start callback timed out", completed.await(5, TimeUnit.SECONDS))
    assertFailure(
      NativeDirectHttpFailure.CANCELLED,
      callbackResult.get() ?: throw AssertionError("cancel-before-start returned no result"),
    )
    assertEquals(1, callbackCount.get())
    assertEquals(0, server.requestCount)
  }

  @Test
  fun cancellationAndSuccessRaceThroughOneTerminalCas() {
    val callbackResult = AtomicReference<NativeDirectHttpResult?>()
    val callbackCount = AtomicInteger(0)
    val responseReady = CountDownLatch(1)
    val allowResponseCompletion = CountDownLatch(1)
    val completion = NativeDirectHttpCompletion { result ->
      callbackCount.incrementAndGet()
      callbackResult.set(result)
    }
    val losingBody = "secret-response".toByteArray()
    val responseThread = thread(name = "direct-http-terminal-race") {
      responseReady.countDown()
      check(allowResponseCompletion.await(5, TimeUnit.SECONDS)) { "race barrier timed out" }
      completion.complete(NativeDirectHttpResult.Success(losingBody))
    }

    assertTrue(responseReady.await(5, TimeUnit.SECONDS))
    assertTrue(completion.cancel())
    allowResponseCompletion.countDown()
    responseThread.join(5_000)

    assertFalse(responseThread.isAlive)
    assertEquals(1, callbackCount.get())
    assertFailure(
      NativeDirectHttpFailure.CANCELLED,
      callbackResult.get() ?: throw AssertionError("terminal race returned no result"),
    )
    assertFalse(
      completion.complete(NativeDirectHttpResult.Failure(NativeDirectHttpFailure.INVALID_REQUEST)),
    )
    assertTrue("losing response bytes must be wiped", losingBody.all { it == 0.toByte() })
    assertFalse(completion.toString().contains("secret-response"))
  }

  @Test
  fun callbackFailureWipesTheTransferredSuccessBody() {
    val body = "secret-response".toByteArray()
    val completion = NativeDirectHttpCompletion {
      throw IllegalStateException("detached callback")
    }

    assertTrue(completion.complete(NativeDirectHttpResult.Success(body)))
    assertTrue("unclaimed response bytes must be wiped", body.all { it == 0.toByte() })
  }

  @Test
  fun httpAndNonCanonicalBase64AreRejectedWithoutNetworkOrSensitiveDiagnostics() {
    requireDebugTestTlsFixture()
    val paddedSignature = "$SIGNATURE_BASE64URL=="
    val invalidHttp = signedRequest(origin = "http://127.0.0.1:80")
    val invalidSignature = signedRequest().copy(
      signature = signedRequest().signature.copy(signatureBase64url = paddedSignature),
    )

    val httpResult = executeAndAwait(invalidHttp)
    val signatureResult = executeAndAwait(invalidSignature)

    assertFailure(NativeDirectHttpFailure.INVALID_REQUEST, httpResult)
    assertFailure(NativeDirectHttpFailure.INVALID_REQUEST, signatureResult)
    assertEquals(0, server.requestCount)
    assertFalse(invalidSignature.toString().contains(paddedSignature))
  }

  @Test
  fun invalidMethodPathBodyAndOwnPrekeyLimitsAreRejectedBeforeNetwork() {
    requireDebugTestTlsFixture()
    val invalid = listOf(
      signedRequest(body = byteArrayOf(1)),
      signedRequest(
        target = "/v1/prekeys/peer",
        responseLimit = NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES,
        method = NativeDirectHttpMethod.POST,
        body = byteArrayOf(1),
      ),
      signedRequest(
        target = "/v1/prekeys",
        responseLimit = NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES,
        method = NativeDirectHttpMethod.POST,
      ),
      signedRequest(
        target = "/v1/prekeys",
        responseLimit = NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES,
        method = NativeDirectHttpMethod.POST,
        body = ByteArray(64 * 1024 + 1),
      ),
      signedRequest(
        target = "/v1/prekeys",
        responseLimit = NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES + 1,
        method = NativeDirectHttpMethod.POST,
        body = byteArrayOf(1),
      ),
      signedRequest(
        target = "/v1/prekeys/${"ab".repeat(32)}/count",
        responseLimit = NativeDirectHttpLimits.OWN_PREKEY_COUNT_BYTES + 1,
      ),
    )

    invalid.forEach { request ->
      assertFailure(NativeDirectHttpFailure.INVALID_REQUEST, executeAndAwait(request))
    }

    assertEquals(0, server.requestCount)
  }

  @Test
  fun testTlsOverrideGuardFailsClosedForReleaseBuilds() {
    val error = assertThrows(IllegalStateException::class.java) {
      requireNativeDirectHttpTestTlsAllowed(debugBuild = false)
    }

    assertEquals("Direct HTTP test TLS is unavailable in release builds", error.message)
    requireNativeDirectHttpTestTlsAllowed(debugBuild = true)
  }

  @Test
  fun releaseLikeVariantRejectsTheRealCustomTestTlsConstructor() {
    assumeFalse("policy assertion applies only to non-debug variants", BuildConfig.DEBUG)
    val heldCertificate = HeldCertificate.Builder()
      .commonName("localhost")
      .addSubjectAlternativeName("localhost")
      .build()
    val clientCertificates = HandshakeCertificates.Builder()
      .addTrustedCertificate(heldCertificate.certificate)
      .build()

    val error = assertThrows(IllegalStateException::class.java) {
      NativeDirectHttpTransport(
        clientCertificates.sslSocketFactory(),
        clientCertificates.trustManager,
      )
    }

    assertEquals("Direct HTTP test TLS is unavailable in release builds", error.message)
  }

  private fun requireDebugTestTlsFixture() {
    assumeTrue("custom TLS fixture is debug-only", BuildConfig.DEBUG)
  }

  private fun signedRequest(
    origin: String = serverOrigin,
    target: String = "/v1/conversations?limit=100",
    responseLimit: Long = NativeDirectHttpLimits.DIRECTORY_BYTES,
    method: NativeDirectHttpMethod = NativeDirectHttpMethod.GET,
    body: ByteArray = byteArrayOf(),
  ): NativeDirectHttpRequest = NativeDirectHttpRequest(
    canonicalServerOrigin = origin,
    requestTarget = target,
    signature = NativeRestSignature(
      version = REST_AUTH_VERSION,
      userId = USER_ID,
      timestampMs = TIMESTAMP_MS,
      nonceBase64url = NONCE_BASE64URL,
      signatureBase64url = SIGNATURE_BASE64URL,
    ),
    responseLimitBytes = responseLimit,
    method = method,
    body = body,
  )

  private fun executeAndAwait(request: NativeDirectHttpRequest): NativeDirectHttpResult =
    executeAndAwait(transport, request)

  private fun executeAndAwait(
    selectedTransport: NativeDirectHttpTransport,
    request: NativeDirectHttpRequest,
  ): NativeDirectHttpResult {
    val result = AtomicReference<NativeDirectHttpResult?>()
    val completed = CountDownLatch(1)
    val call = selectedTransport.createCall(request) { outcome ->
      result.set(outcome)
      completed.countDown()
    }
    call.start()
    assertTrue("Direct HTTP callback timed out", completed.await(5, TimeUnit.SECONDS))
    return result.get() ?: throw AssertionError("Direct HTTP callback returned no result")
  }

  private fun NativeDirectHttpResult.requireSuccessBody(): ByteArray =
    (this as? NativeDirectHttpResult.Success)?.body
      ?: throw AssertionError("expected Direct HTTP success, got $this")

  private fun assertFailure(
    expected: NativeDirectHttpFailure,
    actual: NativeDirectHttpResult,
  ) {
    assertEquals(expected, (actual as? NativeDirectHttpResult.Failure)?.reason)
  }

  private companion object {
    const val USER_ID = "550e8400-e29b-41d4-a716-446655440001"
    const val TIMESTAMP_MS = "1712345678901"
    const val REST_AUTH_VERSION = "2"
    val NONCE_BASE64URL: String = Base64.getUrlEncoder().withoutPadding()
      .encodeToString(ByteArray(32) { index -> (index + 1).toByte() })
    val SIGNATURE_BASE64URL: String = Base64.getUrlEncoder().withoutPadding()
      .encodeToString(ByteArray(64) { index -> (index + 1).toByte() })
  }
}
