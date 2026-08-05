package io.veil.mobile.recovery

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager
import io.veil.mobile.runtime.VeilMobileRuntime

internal class VeilIdentitySetupPackage(
  private val runtime: VeilMobileRuntime,
  private val journal: NativeIdentitySetupJournal,
) : ReactPackage {
  override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> =
    listOf(VeilIdentitySetupModule(reactContext, runtime, journal))

  override fun createViewManagers(
    reactContext: ReactApplicationContext,
  ): List<ViewManager<in Nothing, in Nothing>> = emptyList()
}
