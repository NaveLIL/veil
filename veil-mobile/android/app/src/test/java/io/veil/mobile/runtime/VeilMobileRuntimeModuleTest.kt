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
