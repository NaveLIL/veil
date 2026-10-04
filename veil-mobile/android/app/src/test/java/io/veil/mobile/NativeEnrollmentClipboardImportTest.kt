package io.veil.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeEnrollmentClipboardImportTest {
  @Test
  fun protectsTheWindowBeforeAnyClipboardReadAndRechecksForegroundBeforeStage() {
    val order = mutableListOf<String>()
    assertTrue(NativeEnrollmentClipboardImport.importExplicit(
      isForeground = { order.add("foreground"); true },
      protectWindow = { order.add("secure"); true },
      readPlainText = { order.add("read"); "https://node.example/enroll#invite=test" },
      stage = { order.add("stage"); true },
    ))
    assertEquals(listOf("foreground", "secure", "read", "foreground", "stage"), order)
  }

  @Test
  fun backgroundOrFailedProtectionNeverReadsTheClipboard() {
    for ((foreground, protected) in listOf(false to true, true to false)) {
      assertFalse(NativeEnrollmentClipboardImport.importExplicit(
        isForeground = { foreground },
        protectWindow = { protected },
        readPlainText = { error("must not read") },
        stage = { error("must not stage") },
      ))
    }
  }

  @Test
  fun aForegroundRevocationAfterReadingCannotStage() {
    var foreground = true
    assertFalse(NativeEnrollmentClipboardImport.importExplicit(
      isForeground = { foreground },
      protectWindow = { true },
      readPlainText = { foreground = false; "https://node.example/enroll#invite=test" },
      stage = { error("must not stage") },
    ))
  }

  @Test
  fun nullEmptyOversizedAndCustomSchemeTextCannotStage() {
    for (text in listOf(null, "", "x".repeat(4097), "veil://enroll/v1#invite=test")) {
      assertFalse(NativeEnrollmentClipboardImport.importExplicit(
        isForeground = { true },
        protectWindow = { true },
        readPlainText = { text },
        stage = { error("must not stage") },
      ))
    }
  }

  @Test
  fun oversizedTextIsRejectedBeforeMaterializingIt() {
    val text = object : CharSequence {
      override val length = 4097
      override fun get(index: Int): Char = error("must not access")
      override fun subSequence(startIndex: Int, endIndex: Int): CharSequence = error("must not access")
      override fun toString(): String = error("must not materialize")
    }
    assertFalse(NativeEnrollmentClipboardImport.importExplicit(
      isForeground = { true },
      protectWindow = { true },
      readPlainText = { text },
      stage = { error("must not stage") },
    ))
  }

  @Test
  fun clipboardAndParserFailuresHaveOnlyABooleanOutcome() {
    assertFalse(NativeEnrollmentClipboardImport.importExplicit(
      isForeground = { true },
      protectWindow = { true },
      readPlainText = { throw IllegalStateException("private clipboard diagnostic") },
      stage = { true },
    ))
    assertFalse(NativeEnrollmentClipboardImport.importExplicit(
      isForeground = { true },
      protectWindow = { true },
      readPlainText = { "https://node.example/enroll#invite=test" },
      stage = { throw IllegalArgumentException("private parser diagnostic") },
    ))
  }
}
