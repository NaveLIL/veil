package io.veil.mobile.runtime

/**
 * Android's closed consumer of the append-only PublicFailureCodeV1 registry.
 *
 * Values are presentation identifiers only. They never authorize retry,
 * reconnect, Access Pass replay, or weaker trust checks.
 */
internal enum class PublicFailureCodeV1(val wireValue: String) {
  SETUP_001("VEIL-SETUP-001"),
  SETUP_002("VEIL-SETUP-002"),
  LOCAL_001("VEIL-LOCAL-001"),
  LOCAL_002("VEIL-LOCAL-002"),
  LOCAL_003("VEIL-LOCAL-003"),
  NODE_001("VEIL-NODE-001"),
  NODE_002("VEIL-NODE-002"),
  NODE_003("VEIL-NODE-003"),
  NODE_004("VEIL-NODE-004"),
  PASS_001("VEIL-PASS-001"),
  PASS_002("VEIL-PASS-002"),
  PASS_003("VEIL-PASS-003"),
  RUNTIME_001("VEIL-RUNTIME-001"),
  RUNTIME_002("VEIL-RUNTIME-002"),
  SYNC_001("VEIL-SYNC-001"),
  RUNTIME_999("VEIL-RUNTIME-999"),
  DIRECT_001("VEIL-DIRECT-001"),
  DIRECT_002("VEIL-DIRECT-002"),
}

/** No text, throwable, or server field participates in this mapping. */
internal fun publicFailureCodeV1ForInternalRuntimeCode(code: String): PublicFailureCodeV1 =
  when (code) {
    "E_VEIL_LOCKED" -> PublicFailureCodeV1.LOCAL_001
    "E_VEIL_OPEN" -> PublicFailureCodeV1.LOCAL_002
    "E_VEIL_LOCAL_STATE" -> PublicFailureCodeV1.LOCAL_003
    "E_VEIL_ENDPOINT" -> PublicFailureCodeV1.NODE_001
    "E_VEIL_TRANSPORT" -> PublicFailureCodeV1.NODE_002
    "E_VEIL_AUTH_REJECTED" -> PublicFailureCodeV1.NODE_003
    "E_VEIL_BINDING" -> PublicFailureCodeV1.NODE_004
    "E_VEIL_ACCESS_REQUIRED" -> PublicFailureCodeV1.PASS_001
    "E_VEIL_ACCESS_PASS_REJECTED" -> PublicFailureCodeV1.PASS_002
    "E_VEIL_ACCESS_PASS_LOCAL" -> PublicFailureCodeV1.PASS_003
    "E_VEIL_CONNECTING" -> PublicFailureCodeV1.RUNTIME_001
    "E_VEIL_CANCELLED" -> PublicFailureCodeV1.RUNTIME_002
    "E_VEIL_SYNC" -> PublicFailureCodeV1.SYNC_001
    "E_VEIL_DIRECT_SEND_REJECTED" -> PublicFailureCodeV1.DIRECT_001
    // Legacy E_VEIL_CONNECT/E_VEIL_ACCESS_PASS and every unknown code combine
    // multiple trust states, so a narrower public outcome would be unsafe.
    else -> PublicFailureCodeV1.RUNTIME_999
  }

internal data class RuntimeFailureBridgeV1(
  val internalCode: String,
  val publicCode: PublicFailureCodeV1,
)

/** Keep the legacy internal channel additive, but never forward arbitrary text as a code. */
internal fun runtimeFailureBridgeV1(code: String): RuntimeFailureBridgeV1 {
  val safeInternalCode = when (code) {
    "E_VEIL_ACCESS_PASS",
    "E_VEIL_ACCESS_PASS_LOCAL",
    "E_VEIL_ACCESS_PASS_REJECTED",
    "E_VEIL_ACCESS_REQUIRED",
    "E_VEIL_AUTH_REJECTED",
    "E_VEIL_BINDING",
    "E_VEIL_CANCELLED",
    "E_VEIL_CONNECT",
    "E_VEIL_CONNECTING",
    "E_VEIL_DIRECT_SEND_REJECTED",
    "E_VEIL_DIRECT_SEND_UNAVAILABLE",
    "E_VEIL_DIRECT_SESSION",
    "E_VEIL_DISCONNECT",
    "E_VEIL_ENDPOINT",
    "E_VEIL_LOCAL_STATE",
    "E_VEIL_LOCKED",
    "E_VEIL_OPEN",
    "E_VEIL_RUNTIME",
    "E_VEIL_SYNC",
    "E_VEIL_TRANSPORT" -> code
    else -> "E_VEIL_RUNTIME"
  }
  return RuntimeFailureBridgeV1(
    internalCode = safeInternalCode,
    publicCode = publicFailureCodeV1ForInternalRuntimeCode(safeInternalCode),
  )
}
