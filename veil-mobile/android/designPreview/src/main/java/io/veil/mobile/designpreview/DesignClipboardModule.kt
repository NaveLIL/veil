package io.veil.mobile.designpreview

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

/** Explicit write-only capability of the isolated fixture workbench. */
class DesignClipboardModule(context: ReactApplicationContext) : ReactContextBaseJavaModule(context) {
  override fun getName() = "VeilDesignClipboard"
  @ReactMethod
  fun copyText(text: String, promise: Promise) {
    if (text.isEmpty() || text.length > 4000) { promise.resolve(false); return }
    try {
      val clipboard = reactApplicationContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
      clipboard.setPrimaryClip(ClipData.newPlainText("Veil Design", text))
      promise.resolve(true)
    } catch (_: Exception) { promise.resolve(false) }
  }
}
