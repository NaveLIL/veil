package io.veil.mobile.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class PublicFailureCodeV1Test {
  @Test
  fun `android consumer contains the exact closed v1 vocabulary`() {
    assertEquals(
      listOf(
        "VEIL-SETUP-001",
        "VEIL-SETUP-002",
        "VEIL-LOCAL-001",
        "VEIL-LOCAL-002",
        "VEIL-LOCAL-003",
        "VEIL-NODE-001",
        "VEIL-NODE-002",
        "VEIL-NODE-003",
        "VEIL-NODE-004",
        "VEIL-PASS-001",
        "VEIL-PASS-002",
        "VEIL-PASS-003",
        "VEIL-RUNTIME-001",
        "VEIL-RUNTIME-002",
        "VEIL-SYNC-001",
        "VEIL-RUNTIME-999",
        "VEIL-DIRECT-001",
        "VEIL-DIRECT-002",
      ),
      PublicFailureCodeV1.entries.map { it.wireValue },
    )
  }

  @Test
  fun `every precise internal mapping is fixed and typed`() {
    val expected = linkedMapOf(
      "E_VEIL_LOCKED" to PublicFailureCodeV1.LOCAL_001,
      "E_VEIL_OPEN" to PublicFailureCodeV1.LOCAL_002,
      "E_VEIL_LOCAL_STATE" to PublicFailureCodeV1.LOCAL_003,
      "E_VEIL_ENDPOINT" to PublicFailureCodeV1.NODE_001,
      "E_VEIL_TRANSPORT" to PublicFailureCodeV1.NODE_002,
      "E_VEIL_AUTH_REJECTED" to PublicFailureCodeV1.NODE_003,
      "E_VEIL_BINDING" to PublicFailureCodeV1.NODE_004,
      "E_VEIL_ACCESS_REQUIRED" to PublicFailureCodeV1.PASS_001,
      "E_VEIL_ACCESS_PASS_REJECTED" to PublicFailureCodeV1.PASS_002,
      "E_VEIL_ACCESS_PASS_LOCAL" to PublicFailureCodeV1.PASS_003,
      "E_VEIL_CONNECTING" to PublicFailureCodeV1.RUNTIME_001,
      "E_VEIL_CANCELLED" to PublicFailureCodeV1.RUNTIME_002,
      "E_VEIL_SYNC" to PublicFailureCodeV1.SYNC_001,
      "E_VEIL_DIRECT_SEND_REJECTED" to PublicFailureCodeV1.DIRECT_001,
    )

    expected.forEach { (internalCode, publicCode) ->
      assertEquals(publicCode, publicFailureCodeV1ForInternalRuntimeCode(internalCode))
      assertEquals(
        RuntimeFailureBridgeV1(internalCode, publicCode),
        runtimeFailureBridgeV1(internalCode),
      )
    }
  }

  @Test
  fun `allowed ambiguous internal codes remain visible but fail closed publicly`() {
    val ambiguousAllowedCodes = listOf(
      "E_VEIL_ACCESS_PASS",
      "E_VEIL_CONNECT",
      "E_VEIL_DIRECT_SEND_UNAVAILABLE",
      "E_VEIL_DIRECT_SESSION",
      "E_VEIL_DISCONNECT",
      "E_VEIL_RUNTIME",
    )

    ambiguousAllowedCodes.forEach { internalCode ->
      assertEquals(
        RuntimeFailureBridgeV1(internalCode, PublicFailureCodeV1.RUNTIME_999),
        runtimeFailureBridgeV1(internalCode),
      )
    }
  }

  @Test
  fun `unknown internal detail cannot influence the public identifier`() {
    val secret = "server-secret\nVEIL-PASS-002"
    val mapped = runtimeFailureBridgeV1(secret)

    assertEquals("E_VEIL_RUNTIME", mapped.internalCode)
    assertEquals("VEIL-RUNTIME-999", mapped.publicCode.wireValue)
    assertFalse(mapped.toString().contains("server-secret"))
  }
}
