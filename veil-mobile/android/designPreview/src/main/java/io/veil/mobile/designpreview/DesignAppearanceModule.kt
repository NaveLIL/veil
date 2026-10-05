package io.veil.mobile.designpreview
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactMethod
import io.veil.mobile.presentation.AppearancePickerModule
class DesignAppearanceModule(context: ReactApplicationContext) :
  AppearancePickerModule(context, "VeilDesignAppearance") {
  @ReactMethod override fun pickWallpaper(promise: Promise) = super.pickWallpaper(promise)
}
