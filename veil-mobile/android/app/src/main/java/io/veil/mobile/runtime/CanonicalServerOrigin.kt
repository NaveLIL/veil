package io.veil.mobile.runtime

import java.net.IDN
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.util.Locale

internal data class CanonicalServerOrigin(
  val value: String,
  val websocketUrl: String,
) {
  companion object {
    fun parse(raw: String, allowLoopbackHttp: Boolean = true): CanonicalServerOrigin {
      require(raw.isNotEmpty() && raw.length <= MAX_ORIGIN_CHARS) { "server origin is empty or oversized" }
      require(raw == raw.trim()) { "server origin contains surrounding whitespace" }

      val uri = try {
        URI(raw)
      } catch (_: Exception) {
        throw IllegalArgumentException("server origin is malformed")
      }
      require(!uri.isOpaque) { "server origin must be hierarchical" }
      require(uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) {
        "server origin must not contain credentials, query, or fragment"
      }
      require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") {
        "server origin must not contain a path"
      }

      val scheme = uri.scheme?.lowercase(Locale.ROOT)
        ?: throw IllegalArgumentException("server origin is missing a scheme")
      require(scheme == "https" || scheme == "http") { "server origin must use HTTPS" }
      val host = canonicalHost(uri.host ?: throw IllegalArgumentException("server origin is missing a host"))
      if (scheme == "http") {
        require(allowLoopbackHttp && isLoopback(host)) {
          "insecure HTTP is allowed only for loopback development"
        }
      }
      val port = when {
        uri.port in 1..65535 -> uri.port
        uri.port == -1 && scheme == "https" -> 443
        uri.port == -1 && scheme == "http" -> 80
        else -> throw IllegalArgumentException("server origin has an invalid port")
      }
      val authority = if (host.contains(':')) "[$host]" else host
      val value = "$scheme://$authority:$port"
      val websocketScheme = if (scheme == "https") "wss" else "ws"
      return CanonicalServerOrigin(value, "$websocketScheme://$authority:$port/ws")
    }

    private fun canonicalHost(raw: String): String {
      val host = raw.removePrefix("[").removeSuffix("]")
      require(host.isNotEmpty() && !host.contains('%')) { "server origin has an invalid host" }
      if (host.contains(':')) return canonicalIpv6(host)

      val ascii = try {
        IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
      } catch (_: IllegalArgumentException) {
        throw IllegalArgumentException("server origin has an invalid host")
      }
      require(ascii.isNotEmpty() && ascii.length <= 253 && !ascii.endsWith('.')) {
        "server origin has an invalid host"
      }
      require(ascii.split('.').all { label ->
        label.isNotEmpty() && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-')
      }) { "server origin has an invalid host" }
      if (ascii.all { character -> character.isDigit() || character == '.' }) {
        val octets = ascii.split('.')
        require(octets.size == 4 && octets.all { octet ->
          val value = octet.toIntOrNull()
          octet.isNotEmpty() &&
            (octet == "0" || !octet.startsWith('0')) &&
            value != null && value in 0..255
        }) { "server origin has a non-canonical IPv4 host" }
      }
      return ascii
    }

    private fun canonicalIpv6(raw: String): String {
      val address = try {
        InetAddress.getByName(raw)
      } catch (_: Exception) {
        throw IllegalArgumentException("server origin has an invalid IPv6 host")
      }
      require(address is Inet6Address) { "server origin has an invalid IPv6 host" }
      val bytes = address.address
      val groups = IntArray(8) { index ->
        ((bytes[index * 2].toInt() and 0xff) shl 8) or (bytes[index * 2 + 1].toInt() and 0xff)
      }

      var bestStart = -1
      var bestLength = 0
      var index = 0
      while (index < groups.size) {
        if (groups[index] != 0) {
          index += 1
          continue
        }
        val start = index
        while (index < groups.size && groups[index] == 0) index += 1
        val length = index - start
        if (length >= 2 && length > bestLength) {
          bestStart = start
          bestLength = length
        }
      }

      val result = StringBuilder()
      index = 0
      while (index < groups.size) {
        if (index == bestStart) {
          result.append("::")
          index += bestLength
          if (index == groups.size) break
          continue
        }
        if (result.isNotEmpty() && result.last() != ':') result.append(':')
        result.append(groups[index].toString(16))
        index += 1
      }
      return result.toString()
    }

    private fun isLoopback(host: String): Boolean =
      host == "localhost" || host == "127.0.0.1" || host == "::1"

    private const val MAX_ORIGIN_CHARS = 512
  }
}
