package io.veil.mobile.runtime

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

internal class ParsedNodeAccessPass(
  val canonicalOrigin: String,
  internal val token: ByteArray,
) : AutoCloseable {
  override fun close() {
    token.fill(0)
  }

  override fun toString(): String = "ParsedNodeAccessPass(canonicalOrigin=$canonicalOrigin, token=<redacted>)"
}

internal object NodeAccessPassParser {
  fun isPotentialEnrollment(raw: String): Boolean {
    val uri = try {
      URI(raw)
    } catch (_: Exception) {
      return raw.startsWith("veil://enroll", ignoreCase = true) ||
        targetsMalformedOfficialEnrollment(raw)
    }
    return when (uri.scheme?.lowercase()) {
      "veil" -> uri.host.equals("enroll", ignoreCase = true)
      "https" -> uri.rawPath == "/enroll" || uri.rawPath == "/enroll/"
      else -> false
    }
  }

  private fun targetsMalformedOfficialEnrollment(raw: String): Boolean {
    val target = raw.substringBefore('#').substringBefore('?').lowercase()
    if (!target.startsWith("https://")) return false
    val remainder = target.removePrefix("https://")
    val pathStart = remainder.indexOf('/')
    if (pathStart <= 0) return false
    val authority = remainder.substring(0, pathStart).substringAfterLast('@')
    val host = authority.substringBefore(':')
    val path = remainder.substring(pathStart)
    return host == OFFICIAL_ENROLLMENT_HOST && (path == "/enroll" || path == "/enroll/")
  }

  fun parse(raw: String): ParsedNodeAccessPass {
    require(raw.isNotEmpty() && raw.length <= MAX_LINK_CHARS && raw == raw.trim()) {
      "Node Access Pass link is empty, oversized, or contains surrounding whitespace"
    }
    val uri = try {
      URI(raw)
    } catch (_: Exception) {
      throw IllegalArgumentException("Node Access Pass link is malformed")
    }
    return when (uri.scheme?.lowercase()) {
      "https" -> parseHttps(uri)
      "veil" -> parseCustom(uri)
      else -> throw IllegalArgumentException("unsupported Node Access Pass transport")
    }
  }

  private fun parseHttps(uri: URI): ParsedNodeAccessPass {
    require(
      !uri.isOpaque &&
        uri.rawUserInfo == null &&
        uri.rawQuery == null &&
        uri.rawPath == "/enroll"
    ) { "Node Access Pass HTTPS link is unsupported" }
    val token = decodeToken(requireInviteFragment(uri.rawFragment))
    return try {
      val port = if (uri.port == -1) "" else ":${uri.port}"
      val host = uri.rawAuthority
        ?.substringAfterLast('@')
        ?.let { authority -> if (uri.port == -1) authority else authority.removeSuffix(port) }
        ?: throw IllegalArgumentException("Node Access Pass origin is missing")
      val canonical = CanonicalServerOrigin.parse("https://$host$port", allowLoopbackHttp = false)
      ParsedNodeAccessPass(canonical.value, token)
    } catch (error: Throwable) {
      token.fill(0)
      throw error
    }
  }

  private fun parseCustom(uri: URI): ParsedNodeAccessPass {
    require(
      !uri.isOpaque &&
        uri.host.equals("enroll", ignoreCase = true) &&
        uri.port == -1 &&
        uri.rawUserInfo == null &&
        uri.rawPath == "/v1"
    ) { "custom Node Access Pass link is unsupported" }

    val query = parseExactQuery(uri.rawQuery)
    val origins = query.filter { it.first == "origin" }.map { it.second }
    val queryTokens = query.filter { it.first == "invite" }.map { it.second }
    require(origins.size == 1 && query.size == origins.size + queryTokens.size && queryTokens.size <= 1) {
      "custom Node Access Pass link has no exact HTTPS origin"
    }
    val fragmentToken = uri.rawFragment?.let(::requireInviteFragment)
    val encodedToken = when {
      queryTokens.size == 1 && fragmentToken != null ->
        throw IllegalArgumentException("custom Node Access Pass link has ambiguous tokens")
      queryTokens.size == 1 -> queryTokens.single()
      fragmentToken != null -> fragmentToken
      else -> throw IllegalArgumentException("Node Access Pass token is missing")
    }
    val canonical = CanonicalServerOrigin.parse(origins.single(), allowLoopbackHttp = false)
    require(canonical.value.startsWith("https://")) { "Node Access Pass origin must use HTTPS" }
    return ParsedNodeAccessPass(canonical.value, decodeToken(encodedToken))
  }

  private fun parseExactQuery(rawQuery: String?): List<Pair<String, String>> {
    require(!rawQuery.isNullOrEmpty()) { "custom Node Access Pass link is missing its origin" }
    require(!rawQuery.startsWith('&') && !rawQuery.endsWith('&') && !rawQuery.contains("&&")) {
      "custom Node Access Pass query is malformed"
    }
    return rawQuery.split('&').map { part ->
      val separator = part.indexOf('=')
      require(separator > 0 && separator == part.lastIndexOf('=')) {
        "custom Node Access Pass query is malformed"
      }
      val key = part.substring(0, separator)
      require(key == "origin" || key == "invite") { "custom Node Access Pass link has unknown parameters" }
      key to strictPercentDecode(part.substring(separator + 1))
    }
  }

  private fun strictPercentDecode(value: String): String {
    require(!value.contains('+')) { "custom Node Access Pass query uses ambiguous encoding" }
    return try {
      URLDecoder.decode(value, StandardCharsets.UTF_8.name())
    } catch (_: IllegalArgumentException) {
      throw IllegalArgumentException("custom Node Access Pass query encoding is invalid")
    }
  }

  private fun requireInviteFragment(fragment: String?): String {
    require(fragment != null && fragment.startsWith("invite=")) { "Node Access Pass token is missing" }
    val token = fragment.removePrefix("invite=")
    require(token.isNotEmpty() && !token.contains('&') && !token.contains('=')) {
      "Node Access Pass token is malformed"
    }
    return token
  }

  private fun decodeToken(encoded: String): ByteArray {
    require(TOKEN_PATTERN.matches(encoded)) { "Node Access Pass token is not canonical base64url" }
    val decoded = try {
      Base64.getUrlDecoder().decode(encoded)
    } catch (_: IllegalArgumentException) {
      throw IllegalArgumentException("Node Access Pass token is not canonical base64url")
    }
    if (decoded.size != TOKEN_BYTES || Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != encoded) {
      decoded.fill(0)
      throw IllegalArgumentException("Node Access Pass token must encode exactly 256 bits")
    }
    return decoded
  }

  private val TOKEN_PATTERN = Regex("^[A-Za-z0-9_-]{43}$")
  private const val OFFICIAL_ENROLLMENT_HOST = "veil.erez.pro"
  private const val TOKEN_BYTES = 32
  private const val MAX_LINK_CHARS = 4096
}

internal data class PendingNodeAccessPassView(
  val flowId: String,
  val canonicalOrigin: String,
  val tokenRef: String,
  val expiresInSeconds: Long,
)

internal class NodeAccessPassAttempt internal constructor(
  internal val flowId: ByteArray,
  internal val token: ByteArray,
) : AutoCloseable {
  override fun close() {
    flowId.fill(0)
    token.fill(0)
  }

  override fun toString(): String = "NodeAccessPassAttempt(flowId=<redacted>, token=<redacted>)"
}

internal class NodeAccessPassStore(
  private val clockMillis: () -> Long = { System.nanoTime() / 1_000_000L },
  private val randomBytes: (ByteArray) -> Unit = { SecureRandom().nextBytes(it) },
  private val ttlMillis: Long = DEFAULT_TTL_MILLIS,
) : AutoCloseable {
  private var pending: Pending? = null

  @Synchronized
  fun stage(raw: String): PendingNodeAccessPassView {
    val parsed = NodeAccessPassParser.parse(raw)
    val flowId = ByteArray(FLOW_ID_BYTES)
    val token = try {
      parsed.token.copyOf()
    } finally {
      parsed.close()
    }
    return try {
      randomBytes(flowId)
      val candidate = Pending(flowId, parsed.canonicalOrigin, token, checkedExpiry(clockMillis()))
      val view = candidate.view(clockMillis())
      pending?.close()
      pending = candidate
      view
    } catch (error: Throwable) {
      flowId.fill(0)
      token.fill(0)
      throw error
    }
  }

  @Synchronized
  fun snapshot(): PendingNodeAccessPassView? {
    clearExpired(clockMillis())
    return pending?.view(clockMillis())
  }

  @Synchronized
  fun attempt(expectedFlowId: String, canonicalOrigin: String): NodeAccessPassAttempt? {
    val expected = decodeFlowId(expectedFlowId)
    try {
      clearExpired(clockMillis())
      val current = pending ?: return null
      if (!MessageDigest.isEqual(current.flowId, expected) || current.canonicalOrigin != canonicalOrigin) return null
      return NodeAccessPassAttempt(current.flowId.copyOf(), current.token.copyOf())
    } finally {
      expected.fill(0)
    }
  }

  @Synchronized
  fun clearAfterSuccess(attemptedFlowId: ByteArray) {
    val current = pending ?: return
    if (MessageDigest.isEqual(current.flowId, attemptedFlowId)) {
      current.close()
      pending = null
    }
  }

  @Synchronized
  fun cancel(expectedFlowId: String): Boolean {
    val expected = decodeFlowId(expectedFlowId)
    return try {
      clearExpired(clockMillis())
      val current = pending ?: return false
      if (!MessageDigest.isEqual(current.flowId, expected)) return false
      current.close()
      pending = null
      true
    } finally {
      expected.fill(0)
    }
  }

  @Synchronized
  override fun close() {
    pending?.close()
    pending = null
  }

  private fun clearExpired(now: Long) {
    if (pending?.expiresAtMillis?.let { it <= now } == true) {
      pending?.close()
      pending = null
    }
  }

  private fun checkedExpiry(now: Long): Long = try {
    Math.addExact(now, ttlMillis)
  } catch (_: ArithmeticException) {
    throw IllegalStateException("Node Access Pass expiry overflow")
  }

  private class Pending(
    val flowId: ByteArray,
    val canonicalOrigin: String,
    val token: ByteArray,
    val expiresAtMillis: Long,
  ) : AutoCloseable {
    fun view(now: Long): PendingNodeAccessPassView {
      val digest = MessageDigest.getInstance("SHA-256").digest(token)
      val tokenRef = try {
        digest.copyOfRange(0, 6).toHex()
      } finally {
        digest.fill(0)
      }
      return PendingNodeAccessPassView(
        flowId = flowId.toHex(),
        canonicalOrigin = canonicalOrigin,
        tokenRef = tokenRef,
        expiresInSeconds = ((expiresAtMillis - now).coerceAtLeast(0) + 999) / 1000,
      )
    }

    override fun close() {
      flowId.fill(0)
      token.fill(0)
    }

    override fun toString(): String = "PendingNodeAccessPass(origin=$canonicalOrigin, secrets=<redacted>)"
  }

  companion object {
    private const val FLOW_ID_BYTES = 32
    private const val DEFAULT_TTL_MILLIS = 10 * 60 * 1000L

    private fun decodeFlowId(value: String): ByteArray {
      require(value.length == FLOW_ID_BYTES * 2 && value.all { it in '0'..'9' || it in 'a'..'f' }) {
        "pending Node Access Pass flow ID is invalid"
      }
      return ByteArray(FLOW_ID_BYTES) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
      }
    }
  }
}

private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte) }
