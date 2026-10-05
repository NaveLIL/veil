package io.veil.mobile.designpreview

import android.content.Context
import android.view.accessibility.AccessibilityManager
import android.view.accessibility.AccessibilityNodeInfo
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.UiThreadUtil
import com.facebook.react.uimanager.UIManagerHelper

/** Isolated UI host only: requests Android focus on an existing React view. */
class DesignAccessibilityModule(private val context: ReactApplicationContext) : ReactContextBaseJavaModule(context) {
  override fun getName() = "VeilDesignAccessibility"

  @ReactMethod
  fun focusView(tag: Double, promise: Promise) {
    if (!tag.isFinite() || tag != tag.toInt().toDouble() || tag <= 0) {
      promise.resolve(false)
      return
    }
    UiThreadUtil.runOnUiThread {
      try {
        val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val view = UIManagerHelper.getUIManagerForReactTag(context, tag.toInt())?.resolveView(tag.toInt())
        promise.resolve(manager.isTouchExplorationEnabled && view != null && view.isAttachedToWindow && view.isShown &&
          view.performAccessibilityAction(AccessibilityNodeInfo.ACTION_ACCESSIBILITY_FOCUS, null))
      } catch (_: Exception) {
        // A closed/changed chat may already have removed the target. Never focus another window.
        promise.resolve(false)
      }
    }
  }
}
