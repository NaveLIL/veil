package io.veil.mobile.designpreview
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactMethod
import io.veil.mobile.presentation.AppearancePreferencesModule
/** Compatibility registration; storage implementation is shared, never an account adapter. */
class DesignPreferencesModule(context: ReactApplicationContext) :
  AppearancePreferencesModule(context, "VeilDesignPreferences", "design-appearance") {
  // React Native discovers declared methods, not inherited @ReactMethod annotations.
  @ReactMethod override fun loadPreferences(promise: Promise) = super.loadPreferences(promise)
  @ReactMethod override fun savePreferences(json: String, promise: Promise) = super.savePreferences(json, promise)
}
