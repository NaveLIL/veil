package io.veil.mobile.presentation

import android.graphics.RenderEffect
import android.graphics.Shader
import android.os.Build
import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ThemedReactContext
import com.facebook.react.uimanager.ViewManager
import com.facebook.react.uimanager.annotations.ReactProp
import com.facebook.react.views.view.ReactViewGroup
import com.facebook.react.views.view.ReactViewManager

/** Live GPU blur of this view's subtree. No bitmap capture, I/O, account or transport. */
class VeilBlurView(context: ThemedReactContext) : ReactViewGroup(context) {
  var requestedRadius = 0f
  private var appliedRadius = -1f
  private var effect: RenderEffect? = null
  fun applyBlur() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
    val radius = requestedRadius * resources.displayMetrics.density
    if (radius != appliedRadius) {
      appliedRadius = radius
      effect = if (radius <= 0f) null else RenderEffect.createBlurEffect(radius, radius, Shader.TileMode.CLAMP)
    }
    setRenderEffect(effect)
  }
}
class VeilBlurViewManager : ReactViewManager() {
  override fun getName() = "VeilLiveBlurView"
  override fun createViewInstance(context: ThemedReactContext) = VeilBlurView(context)
  @ReactProp(name = "blurRadius", defaultFloat = 0f)
  fun setBlurRadius(view: ReactViewGroup, radius: Float) {
    (view as VeilBlurView).requestedRadius = if (radius.isFinite()) radius.coerceIn(0f, 32f) else 0f
    view.applyBlur()
  }
  override fun onAfterUpdateTransaction(view: ReactViewGroup) {
    // RN's BaseViewManager clears RenderEffect while applying its own filter.
    // Restore our cached live effect after the inherited transaction finishes.
    super.onAfterUpdateTransaction(view)
    (view as VeilBlurView).applyBlur()
  }
  override fun onDropViewInstance(view: ReactViewGroup) {
    setBlurRadius(view, 0f)
    super.onDropViewInstance(view)
  }
}

class VeilPresentationPackage(private val appearance: Boolean = true) : ReactPackage {
  override fun createNativeModules(context: ReactApplicationContext): List<NativeModule> =
    if (appearance) listOf(AppearancePreferencesModule(context), AppearancePickerModule(context), PresentationClipboardModule(context)) else emptyList()
  override fun createViewManagers(context: ReactApplicationContext): List<ViewManager<*, *>> = listOf(VeilBlurViewManager())
}
