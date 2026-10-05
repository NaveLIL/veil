package io.veil.mobile.presentation

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

/** Explicit user-selected text only. Write-only; no logs, clipboard reads or transport. */
class PresentationClipboardModule(context: ReactApplicationContext) : ReactContextBaseJavaModule(context) {
  override fun getName() = "VeilPresentationClipboard"
  @ReactMethod fun copyText(text: String, promise: Promise) {
    if (text.isEmpty() || text.toByteArray(Charsets.UTF_8).size > 65536) { promise.resolve(false); return }
    try {
      val clip = ClipData.newPlainText("Veil", text)
      clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
      val manager = reactApplicationContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
      manager.setPrimaryClip(clip)
      promise.resolve(true)
    } catch (_: Exception) { promise.resolve(false) }
  }
}
