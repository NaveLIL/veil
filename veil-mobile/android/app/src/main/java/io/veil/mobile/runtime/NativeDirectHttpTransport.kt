package io.veil.mobile.runtime

import androidx.annotation.VisibleForTesting
import io.veil.mobile.BuildConfig
import java.net.URI
import java.util.UUID
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okio.ByteString.Companion.decodeBase64

/** Response limits mirrored from the native Direct contract. */
internal object NativeDirectHttpLimits {
  const val DIRECTORY_BYTES: Long = 8L * 1024L * 1024L
  const val PREKEY_BYTES: Long = 64L * 1024L
  const val OWN_PREKEY_COUNT_BYTES: Long = 64L * 1024L
  const val OWN_PREKEY_UPLOAD_BYTES: Long = 4L * 1024L
}

internal enum class NativeDirectHttpMethod {
  GET,
  POST,
}

/**
 * Native-only signed HTTP input. Lease/request capabilities are deliberately
 * absent: the runtime retains them and returns raw response bytes to UniFFI.
 */
internal data class NativeDirectHttpRequest(
  val canonicalServerOrigin: String,
  val requestTarget: String,
  val signature: NativeRestSignature,
  val responseLimitBytes: Long,
  val method: NativeDirectHttpMethod = NativeDirectHttpMethod.GET,
  val body: ByteArray = byteArrayOf(),
) {
  override fun toString(): String =
    "NativeDirectHttpRequest(" +
      "method=$method, " +
      "canonicalServerOrigin=[REDACTED], " +
      "requestTarget=[REDACTED], " +
      "signature=[REDACTED], " +
      "body=[REDACTED], " +
      "responseLimitBytes=$responseLimitBytes)"
}

internal enum class NativeDirectHttpFailure {
  INVALID_REQUEST,
  CANCELLED,
  NETWORK,
  UNEXPECTED_STATUS,
  RESPONSE_TOO_LARGE,
}

internal sealed interface NativeDirectHttpResult {
  class Success(val body: ByteArray) : NativeDirectHttpResult {
    override fun toString(): String = "NativeDirectHttpResult.Success(bodyBytes=${body.size})"
  }

  data class Failure(val reason: NativeDirectHttpFailure) : NativeDirectHttpResult
}

internal fun NativeDirectHttpResult.wipeSensitiveBody() {
  if (this is NativeDirectHttpResult.Success) body.fill(0)
}

internal fun interface NativeDirectHttpCallback {
  fun onComplete(result: NativeDirectHttpResult)
}

/**
 * Implementations must synchronously snapshot [NativeDirectHttpRequest.body]
 * while creating an unstarted call. The runtime wipes its caller-owned wire
 * buffer as soon as [createCall] returns, atomically attaches the call to the
 * active lease, and only then invokes [NativeDirectHttpCall.start]. Callbacks
 * receive only the bounded response bytes.
 */
internal fun interface NativeDirectHttpExecutor {
  fun createCall(
    request: NativeDirectHttpRequest,
    callback: NativeDirectHttpCallback,
  ): NativeDirectHttpCall
}

internal interface NativeDirectHttpCall : AutoCloseable {
  /** Starts at most once. A call cancelled before this point must never start. */
  fun start()

  fun cancel()

  override fun close() = cancel()
}

@VisibleForTesting
internal fun requireNativeDirectHttpTestTlsAllowed(debugBuild: Boolean) {
  check(debugBuild) { "Direct HTTP test TLS is unavailable in release builds" }
}

/**
 * Single linearization point shared by completion and cancellation.
 * Whichever terminal CAS wins owns the sole callback publication.
 */
internal class NativeDirectHttpCompletion(
  private val callback: NativeDirectHttpCallback,
) {
  private val state = AtomicReference(TerminalState.ACTIVE)

  fun complete(result: NativeDirectHttpResult): Boolean {
    if (!state.compareAndSet(TerminalState.ACTIVE, TerminalState.COMPLETED)) {
      result.wipeSensitiveBody()
      return false
    }
    publish(result)
    return true
  }

  fun cancel(onCancellationWon: () -> Unit = {}): Boolean {
    if (!state.compareAndSet(TerminalState.ACTIVE, TerminalState.CANCELLED)) return false
    try {
      onCancellationWon()
    } catch (_: RuntimeException) {
      // Cancellation remains terminal even if the underlying call is already gone.
    } finally {
      publish(NativeDirectHttpResult.Failure(NativeDirectHttpFailure.CANCELLED))
    }
    return true
  }

  fun isActive(): Boolean = state.get() == TerminalState.ACTIVE

  private fun publish(result: NativeDirectHttpResult) {
    try {
      callback.onComplete(result)
    } catch (_: RuntimeException) {
      result.wipeSensitiveBody()
      // A detached runtime callback must not crash OkHttp's dispatcher.
    }
  }

  override fun toString(): String = "NativeDirectHttpCompletion(state=${state.get()})"

  private enum class TerminalState {
    ACTIVE,
    CANCELLED,
    COMPLETED,
  }
}

/**
 * Isolated asynchronous HTTP executor for native Direct directory/prekey
 * GETs and the exact own-prekey publication POST.
 *
 * Production always starts from a clean OkHttp builder and therefore keeps
 * Android's system trust manager, hostname verifier, DNS, dispatcher, cookie
 * policy, authenticators, and empty interceptor lists. Tests can replace only
 * the trust material for a local TLS server; hostname verification stays on.
 */
internal class NativeDirectHttpTransport private constructor(
  testTls: TestTls?,
) : NativeDirectHttpExecutor {
  constructor() : this(null)

  @VisibleForTesting
  internal constructor(
    sslSocketFactory: SSLSocketFactory,
    trustManager: X509TrustManager,
  ) : this(debugTestTls(sslSocketFactory, trustManager))

  private val client = OkHttpClient.Builder()
    .apply {
      testTls?.let { tls -> sslSocketFactory(tls.sslSocketFactory, tls.trustManager) }
    }
    .followRedirects(false)
    .followSslRedirects(false)
    .retryOnConnectionFailure(false)
    .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
    .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
    .callTimeout(CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
    .build()

  override fun createCall(
    request: NativeDirectHttpRequest,
    callback: NativeDirectHttpCallback,
  ): NativeDirectHttpCall {
    val completion = NativeDirectHttpCompletion(callback)
    val prepared = try {
      prepareRequest(request)
    } catch (_: IllegalArgumentException) {
      return RejectedDirectHttpCall(client.dispatcher.executorService, completion)
    }

    val call = client.newCall(prepared)
    val networkCallback = object : Callback {
      override fun onFailure(call: Call, error: java.io.IOException) {
        completion.complete(NativeDirectHttpResult.Failure(NativeDirectHttpFailure.NETWORK))
      }

      override fun onResponse(call: Call, response: Response) {
        val result = try {
          response.use { received ->
            when {
              !completion.isActive() -> NativeDirectHttpResult.Failure(NativeDirectHttpFailure.CANCELLED)
              received.code != HTTP_OK ->
                NativeDirectHttpResult.Failure(NativeDirectHttpFailure.UNEXPECTED_STATUS)
              else -> received.body?.let { body ->
                readBounded(body, request.responseLimitBytes)
              } ?: NativeDirectHttpResult.Failure(NativeDirectHttpFailure.NETWORK)
            }
          }
        } catch (_: java.io.IOException) {
          NativeDirectHttpResult.Failure(NativeDirectHttpFailure.NETWORK)
        } catch (_: RuntimeException) {
          NativeDirectHttpResult.Failure(NativeDirectHttpFailure.NETWORK)
        }
        completion.complete(result)
      }
    }
    return OkHttpDirectCall(call, networkCallback, completion)
  }

  @VisibleForTesting
  internal fun prepareRequest(input: NativeDirectHttpRequest): Request {
    require(input.responseLimitBytes in 1..NativeDirectHttpLimits.DIRECTORY_BYTES) {
      "Direct response limit is invalid"
    }
    when (input.method) {
      NativeDirectHttpMethod.GET -> {
        require(input.body.isEmpty()) { "Direct GET body must be empty" }
        if (isOwnPreKeyCountTarget(input.requestTarget)) {
          require(input.responseLimitBytes <= NativeDirectHttpLimits.OWN_PREKEY_COUNT_BYTES) {
            "Own prekey count response limit is invalid"
          }
        }
      }
      NativeDirectHttpMethod.POST -> {
        require(input.requestTarget == OWN_PREKEY_UPLOAD_TARGET) {
          "Direct POST target is invalid"
        }
        require(input.body.size in 1..MAX_REQUEST_BODY_BYTES) {
          "Own prekey upload body is empty or oversized"
        }
        require(input.responseLimitBytes <= NativeDirectHttpLimits.OWN_PREKEY_UPLOAD_BYTES) {
          "Own prekey upload response limit is invalid"
        }
      }
    }
    require(input.canonicalServerOrigin.startsWith("https://")) {
      "Direct transport requires HTTPS"
    }
    val canonical = CanonicalServerOrigin.parse(
      input.canonicalServerOrigin,
      allowLoopbackHttp = false,
    )
    require(canonical.value == input.canonicalServerOrigin) {
      "Direct origin is not canonical"
    }

    requireValidRequestTarget(input.requestTarget)
    val url = (canonical.value + input.requestTarget).toHttpUrlOrNull()
      ?: throw IllegalArgumentException("Direct request URL is invalid")
    val encodedTarget = buildString {
      append(url.encodedPath)
      url.encodedQuery?.let { query ->
        append('?')
        append(query)
      }
    }
    require(encodedTarget == input.requestTarget) {
      "Direct request target changed during URL parsing"
    }

    val authority = URI(canonical.value).rawAuthority
      ?: throw IllegalArgumentException("Direct origin has no authority")
    require(authority == canonical.value.removePrefix("https://")) {
      "Direct origin authority is not canonical"
    }
    requireValidSignature(input.signature)

    val builder = Request.Builder()
      .url(url)
      .header("Host", authority)
      .header("Accept", JSON_MEDIA_TYPE)
      .header("X-Veil-User", input.signature.userId)
      .header("X-Veil-Timestamp", input.signature.timestampMs)
      .header("X-Veil-Signature", input.signature.signatureBase64)
    when (input.method) {
      NativeDirectHttpMethod.GET -> builder.get()
      NativeDirectHttpMethod.POST -> {
        // OkHttp writes asynchronously. Own an exact copy so the caller can
        // clear or reuse its buffer without changing the signed wire body.
        val exactBody = input.body.copyOf()
        builder.post(exactBody.toRequestBody(JSON_MEDIA_TYPE_VALUE))
      }
    }
    return builder.build()
  }

  private fun isOwnPreKeyCountTarget(target: String): Boolean =
    OWN_PREKEY_COUNT_TARGET.matches(target)

  private fun requireValidRequestTarget(target: String) {
    require(target.isNotEmpty() && target.length <= MAX_REQUEST_TARGET_CHARS) {
      "Direct request target is empty or oversized"
    }
    require(target[0] == '/' && '#' !in target) { "Direct request target is invalid" }
    require(target.all { character -> character.code in 0x21..0x7e }) {
      "Direct request target must be printable ASCII"
    }
  }

  private fun requireValidSignature(signature: NativeRestSignature) {
    val userId = try {
      UUID.fromString(signature.userId).toString()
    } catch (_: IllegalArgumentException) {
      throw IllegalArgumentException("Direct signature user is invalid")
    }
    require(userId == signature.userId) { "Direct signature user is not canonical" }

    val timestamp = signature.timestampMs.toLongOrNull()
    require(timestamp != null && timestamp >= 0 && timestamp.toString() == signature.timestampMs) {
      "Direct signature timestamp is invalid"
    }
    val signatureBytes = signature.signatureBase64.decodeBase64()
      ?: throw IllegalArgumentException("Direct signature is invalid")
    require(
      signatureBytes.size == ED25519_SIGNATURE_BYTES &&
        signatureBytes.base64() == signature.signatureBase64
    ) { "Direct signature is invalid" }
  }

  private fun readBounded(
    body: ResponseBody,
    responseLimitBytes: Long,
  ): NativeDirectHttpResult {
    val declaredLength = body.contentLength()
    if (declaredLength > responseLimitBytes) {
      return NativeDirectHttpResult.Failure(NativeDirectHttpFailure.RESPONSE_TOO_LARGE)
    }

    val maximumBytes = Math.toIntExact(
      if (declaredLength >= 0L) {
        minOf(responseLimitBytes + 1L, declaredLength + 1L)
      } else {
        responseLimitBytes + 1L
      },
    )
    val scratch = ByteArray(maximumBytes)
    var used = 0
    return try {
      val input = body.byteStream()
      while (used < scratch.size) {
        val read = input.read(scratch, used, minOf(READ_CHUNK_BYTES, scratch.size - used))
        if (read == -1) break
        if (read == 0) throw java.io.IOException("Direct response read made no progress")
        used += read
      }
      if (used > responseLimitBytes) {
        NativeDirectHttpResult.Failure(NativeDirectHttpFailure.RESPONSE_TOO_LARGE)
      } else if (declaredLength >= 0L && used.toLong() != declaredLength) {
        NativeDirectHttpResult.Failure(NativeDirectHttpFailure.NETWORK)
      } else {
        NativeDirectHttpResult.Success(scratch.copyOf(used))
      }
    } finally {
      // Do not leave a second copy of directory/prekey material in an Okio
      // segment pool or temporary heap buffer after ownership is transferred.
      scratch.fill(0)
    }
  }

  private class OkHttpDirectCall(
    private val call: Call,
    private val callback: Callback,
    private val completion: NativeDirectHttpCompletion,
  ) : NativeDirectHttpCall {
    private val state = AtomicReference(CallState.CREATED)

    override fun start() {
      if (!state.compareAndSet(CallState.CREATED, CallState.STARTED)) return
      try {
        call.enqueue(callback)
      } catch (_: RuntimeException) {
        completion.complete(NativeDirectHttpResult.Failure(NativeDirectHttpFailure.NETWORK))
      }
    }

    override fun cancel() {
      while (true) {
        when (state.get()) {
          CallState.CANCELLED -> return
          CallState.CREATED -> if (state.compareAndSet(CallState.CREATED, CallState.CANCELLED)) {
            completion.cancel()
            return
          }
          CallState.STARTED -> if (state.compareAndSet(CallState.STARTED, CallState.CANCELLED)) {
            completion.cancel { call.cancel() }
            return
          }
        }
      }
    }

    override fun toString(): String = "NativeDirectHttpCall($completion)"
  }

  private class RejectedDirectHttpCall(
    private val callbackExecutor: Executor,
    private val completion: NativeDirectHttpCompletion,
  ) : NativeDirectHttpCall {
    private val state = AtomicReference(CallState.CREATED)

    override fun start() {
      if (!state.compareAndSet(CallState.CREATED, CallState.STARTED)) return
      try {
        callbackExecutor.execute {
          completion.complete(NativeDirectHttpResult.Failure(NativeDirectHttpFailure.INVALID_REQUEST))
        }
      } catch (_: RuntimeException) {
        completion.complete(NativeDirectHttpResult.Failure(NativeDirectHttpFailure.INVALID_REQUEST))
      }
    }

    override fun cancel() {
      while (true) {
        when (state.get()) {
          CallState.CANCELLED -> return
          CallState.CREATED -> if (state.compareAndSet(CallState.CREATED, CallState.CANCELLED)) {
            completion.cancel()
            return
          }
          CallState.STARTED -> if (state.compareAndSet(CallState.STARTED, CallState.CANCELLED)) {
            completion.cancel()
            return
          }
        }
      }
    }

    override fun toString(): String = "NativeDirectHttpCall($completion)"
  }

  private enum class CallState {
    CREATED,
    STARTED,
    CANCELLED,
  }

  private data class TestTls(
    val sslSocketFactory: SSLSocketFactory,
    val trustManager: X509TrustManager,
  )

  private companion object {
    /** Guard must run before TestTls or an OkHttp client is constructed. */
    fun debugTestTls(
      sslSocketFactory: SSLSocketFactory,
      trustManager: X509TrustManager,
    ): TestTls {
      requireNativeDirectHttpTestTlsAllowed(BuildConfig.DEBUG)
      return TestTls(sslSocketFactory, trustManager)
    }

    const val HTTP_OK = 200
    const val JSON_MEDIA_TYPE = "application/json"
    val JSON_MEDIA_TYPE_VALUE = JSON_MEDIA_TYPE.toMediaType()
    const val OWN_PREKEY_UPLOAD_TARGET = "/v1/prekeys"
    val OWN_PREKEY_COUNT_TARGET = Regex("^/v1/prekeys/[0-9a-f]{64}/count$")
    const val MAX_REQUEST_TARGET_CHARS = 8 * 1024
    const val MAX_REQUEST_BODY_BYTES = 64 * 1024
    const val ED25519_SIGNATURE_BYTES = 64
    const val READ_CHUNK_BYTES = 8 * 1024
    const val CONNECT_TIMEOUT_SECONDS = 10L
    const val READ_TIMEOUT_SECONDS = 20L
    const val CALL_TIMEOUT_SECONDS = 30L
  }
}
