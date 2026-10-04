package io.veil.mobile.runtime

import com.facebook.react.bridge.JavaOnlyMap
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.WritableMap
import java.lang.reflect.Proxy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class VeilMobileRuntimeModuleTest {
  @Test
  fun `contacts expose only closed public results and sanitized errors`() {
    val found = capturePromise()
    found.promise.publishContactOperationResult(
      NativeContactOperationResult.Found("peer-id", "alice")) { JavaOnlyMap() }
    val foundMap = found.resolveCalls.single().single() as WritableMap
    assertEquals(mapOf("userId" to "peer-id", "username" to "alice"), foundMap.toHashMap())
    val missing = capturePromise()
    missing.promise.publishContactOperationResult(NativeContactOperationResult.NotFound) {
      JavaOnlyMap()
    }
    assertEquals(listOf(listOf<Any?>(null)), missing.resolveCalls)
    val created = capturePromise()
    created.promise.publishContactOperationResult(
      NativeContactOperationResult.Created("conversation-id")) { JavaOnlyMap() }
    val createdMap = created.resolveCalls.single().single() as WritableMap
    assertEquals(mapOf("conversationId" to "conversation-id"), createdMap.toHashMap())
    val unavailable = capturePromise()
    unavailable.promise.publishContactOperationResult(NativeContactOperationResult.Unavailable) {
      JavaOnlyMap()
    }
    assertExactRejection(unavailable, "E_VEIL_RUNTIME", "VEIL-RUNTIME-999",
      listOf("signature", "body", "identity_key", "signing_key"))
  }

  @Test
  fun `React production surface has no contact signer request or parser capability`() {
    val names = VeilMobileRuntimeModule::class.java.declaredMethods.map { it.name }.toSet()
    listOf("prepareContactSearch", "prepareCreateDirect", "parseContactSearchResponse",
      "parseCreateDirectResponse").forEach { assertFalse(names.contains(it)) }
  }

  @Test
  fun `V2 send exports publish only exact committed identity and never legacy null`() {
    val names = VeilMobileRuntimeModule::class.java.declaredMethods.map { it.name }.toSet()
    assertFalse(names.contains("sendDirectText"))
    assertFalse(names.contains("projectDirectMessages"))
    assertEquals(true, names.contains("sendDirectTextV2"))
    assertEquals(true, names.contains("projectDirectMessagesV2"))
    val receipt = NativeDirectTextAcceptanceV2("40000000-0000-4000-8000-000000000001",
      "40000000-0000-4000-8000-000000000001")
    val accepted = capturePromise()
    accepted.promise.publishDirectTextSendResultV2(
      NativeDirectTextSendResultV2(NativeDirectTextSendResult.ACCEPTED, receipt)) { JavaOnlyMap() }
    val published = accepted.resolveCalls.single().single() as WritableMap
    assertEquals(mapOf("clientMessageId" to receipt.clientMessageId,
      "localMessageId" to receipt.localMessageId), published.toHashMap())
    assertEquals(1, accepted.completionCount())
    listOf(null, receipt.copy(localMessageId = "40000000-0000-4000-8000-000000000002"))
      .forEach { malformed ->
        val denied = capturePromise()
        denied.promise.publishDirectTextSendResultV2(
          NativeDirectTextSendResultV2(NativeDirectTextSendResult.ACCEPTED, malformed)) {
          JavaOnlyMap()
        }
        assertExactRejection(denied, "E_VEIL_DIRECT_SEND_UNAVAILABLE", "VEIL-RUNTIME-999",
          listOf(receipt.clientMessageId))
      }
  }

  @Test
  fun `Direct session unavailable routes through one sanitized rejection`() {
    val capture = capturePromise()

    capture.promise.publishDirectSessionResult(
      NativeDirectSessionActionResult.Unavailable,
    ) { JavaOnlyMap() }

    assertExactRejection(
      capture = capture,
      expectedInternalCode = "E_VEIL_DIRECT_SESSION",
      expectedPublicCode = "VEIL-RUNTIME-999",
      forbiddenText = listOf("Unable to establish the secure Direct session"),
    )
  }

  @Test
  fun `Direct text result routing preserves accepted and separates definite rejection`() {
    listOf(
      SendRejectionCase(
        result = NativeDirectTextSendResult.REJECTED,
        expectedInternalCode = "E_VEIL_DIRECT_SEND_REJECTED",
        expectedPublicCode = "VEIL-DIRECT-001",
        forbiddenText = "Direct message was rejected",
      ),
      SendRejectionCase(
        result = NativeDirectTextSendResult.UNAVAILABLE,
        expectedInternalCode = "E_VEIL_DIRECT_SEND_UNAVAILABLE",
        expectedPublicCode = "VEIL-RUNTIME-999",
        forbiddenText = "Direct messaging is unavailable",
      ),
    ).forEach { case ->
      val capture = capturePromise()

      capture.promise.publishDirectTextSendResult(case.result) { JavaOnlyMap() }

      assertExactRejection(
        capture = capture,
        expectedInternalCode = case.expectedInternalCode,
        expectedPublicCode = case.expectedPublicCode,
        forbiddenText = listOf(case.forbiddenText),
      )
    }

    val accepted = capturePromise()
    accepted.promise.publishDirectTextSendResult(NativeDirectTextSendResult.ACCEPTED) {
      JavaOnlyMap()
    }

    assertEquals(listOf(listOf<Any?>(null)), accepted.resolveCalls)
    assertEquals(0, accepted.rejectionCalls.size)
    assertEquals(1, accepted.completionCount())
  }

  @Test
  fun `publication exceptions route through one sanitized typed or generic rejection`() {
    val typed = capturePromise()
    typed.promise.rejectRuntimePublicationFailure(
      VeilMobileRuntimeException(
        "E_VEIL_DIRECT_SEND_UNAVAILABLE",
        "typed throwable detail must not cross",
      ),
    ) { JavaOnlyMap() }
    assertExactRejection(
      capture = typed,
      expectedInternalCode = "E_VEIL_DIRECT_SEND_UNAVAILABLE",
      expectedPublicCode = "VEIL-RUNTIME-999",
      forbiddenText = listOf("typed throwable detail must not cross"),
    )

    val generic = capturePromise()
    generic.promise.rejectRuntimePublicationFailure(
      IllegalStateException("generic throwable detail must not cross"),
    ) { JavaOnlyMap() }
    assertExactRejection(
      capture = generic,
      expectedInternalCode = "E_VEIL_RUNTIME",
      expectedPublicCode = "VEIL-RUNTIME-999",
      forbiddenText = listOf("generic throwable detail must not cross"),
    )
  }

  private fun capturePromise(): PromiseCapture {
    val resolveCalls = mutableListOf<List<Any?>>()
    val rejectionCalls = mutableListOf<List<Any?>>()
    val promise = Proxy.newProxyInstance(
      Promise::class.java.classLoader,
      arrayOf(Promise::class.java),
    ) { _, method, arguments ->
      when (method.name) {
        "resolve" -> resolveCalls.add(arguments?.toList().orEmpty())
        "reject" -> rejectionCalls.add(arguments?.toList().orEmpty())
        else -> error("Unexpected Promise method: ${method.name}")
      }
      null
    } as Promise
    return PromiseCapture(promise, resolveCalls, rejectionCalls)
  }

  private fun assertExactRejection(
    capture: PromiseCapture,
    expectedInternalCode: String,
    expectedPublicCode: String,
    forbiddenText: List<String>,
  ) {
    assertEquals(0, capture.resolveCalls.size)
    assertEquals(1, capture.rejectionCalls.size)
    assertEquals(1, capture.completionCount())
    val arguments = capture.rejectionCalls.single()
    assertEquals(3, arguments.size)
    assertEquals(expectedInternalCode, arguments[0])
    assertEquals("Native mobile runtime operation failed", arguments[1])
    assertFalse(arguments.any { it is Throwable })
    val userInfo = arguments[2] as WritableMap
    assertEquals(
      mapOf("publicFailureCodeV1" to expectedPublicCode),
      userInfo.toHashMap(),
    )
    val publishedText = buildList {
      arguments.filterIsInstance<String>().forEach(::add)
      userInfo.toHashMap().forEach { (key, value) ->
        add(key)
        add(value.toString())
      }
    }
    forbiddenText.forEach { raw ->
      assertFalse("raw failure text crossed the Promise boundary", publishedText.any { raw in it })
    }
  }

  private data class PromiseCapture(
    val promise: Promise,
    val resolveCalls: List<List<Any?>>,
    val rejectionCalls: List<List<Any?>>,
  ) {
    fun completionCount(): Int = resolveCalls.size + rejectionCalls.size
  }

  private data class SendRejectionCase(
    val result: NativeDirectTextSendResult,
    val expectedInternalCode: String,
    val expectedPublicCode: String,
    val forbiddenText: String,
  )
}
