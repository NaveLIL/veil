package io.veil.mobile.designpreview

import android.app.Application
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.ReactNativeHost
import com.facebook.react.ReactPackage
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.load
import com.facebook.react.defaults.DefaultReactHost.getDefaultReactHost
import com.facebook.react.defaults.DefaultReactNativeHost
import com.facebook.react.shell.MainReactPackage
import com.facebook.react.soloader.OpenSourceMergedSoMapping
import com.facebook.soloader.SoLoader
import com.th3rdwave.safeareacontext.SafeAreaContextPackage
import com.horcrux.svg.SvgPackage
import com.zoontek.rnedgetoedge.EdgeToEdgePackage

/** No Veil runtime, journals, crypto bridges, Expo account modules or private data. */
class DesignApplication : Application(), ReactApplication {
  override val reactNativeHost: ReactNativeHost = object : DefaultReactNativeHost(this) {
    override fun getPackages(): List<ReactPackage> = listOf(
      MainReactPackage(), SafeAreaContextPackage(), SvgPackage(), EdgeToEdgePackage(),
      DesignAppearancePackage(),
    )
    override fun getJSMainModuleName() = "design-preview-index"
    override fun getUseDeveloperSupport() = BuildConfig.DEBUG
    override val isNewArchEnabled = BuildConfig.IS_NEW_ARCHITECTURE_ENABLED
    override val isHermesEnabled = BuildConfig.IS_HERMES_ENABLED
  }
  override val reactHost: ReactHost
    get() = getDefaultReactHost(applicationContext, reactNativeHost)
  override fun onCreate() {
    super.onCreate()
    SoLoader.init(this, OpenSourceMergedSoMapping)
    if (BuildConfig.IS_NEW_ARCHITECTURE_ENABLED) load()
  }
}
