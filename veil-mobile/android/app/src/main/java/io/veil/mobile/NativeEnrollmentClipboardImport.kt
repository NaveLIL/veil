package io.veil.mobile

/** Explicit foreground import policy; neither the clipboard nor its bearer is published to React. */
internal object NativeEnrollmentClipboardImport {
  fun importExplicit(
    isForeground: () -> Boolean,
    protectWindow: () -> Boolean,
    readPlainText: () -> CharSequence?,
    stage: (String) -> Boolean,
  ): Boolean = try {
    if (!isForeground() || !protectWindow()) {
      false
    } else {
      val text = readPlainText()
      if (text == null || text.isEmpty() || text.length > MAX_LINK_CHARS) {
        false
      } else {
        val raw = text.toString()
        // This entry point imports the original HTTPS invitation, without
        // broadening the tester's production deep-link intent filters.
        raw.startsWith("https://") && raw.length <= MAX_LINK_CHARS &&
          isForeground() && stage(raw)
      }
    }
  } catch (_: Exception) {
    // Clipboard/provider/parser diagnostics can contain a bearer. Return only
    // a coarse result and leave the existing clipboard untouched.
    false
  }

  private const val MAX_LINK_CHARS = 4096
}
