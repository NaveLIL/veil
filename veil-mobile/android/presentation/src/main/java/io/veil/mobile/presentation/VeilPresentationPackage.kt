package io.veil.mobile.presentation

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

class VeilPresentationPackage(private val appearance: Boolean = true) : ReactPackage {
  override fun createNativeModules(context: ReactApplicationContext): List<NativeModule> =
    if (appearance) listOf(AppearancePreferencesModule(context), AppearancePickerModule(context), PresentationClipboardModule(context)) else emptyList()
  override fun createViewManagers(context: ReactApplicationContext): List<ViewManager<*, *>> = listOf(VeilBlurViewManager())
}
