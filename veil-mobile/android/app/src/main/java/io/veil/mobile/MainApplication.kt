package io.veil.mobile

import android.app.Activity
import android.app.Application
import android.content.res.Configuration
import android.os.Bundle
import android.os.Handler
import android.os.Looper

import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactNativeHost
import com.facebook.react.ReactPackage
import com.facebook.react.ReactHost
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.load
import com.facebook.react.defaults.DefaultReactNativeHost
import com.facebook.react.soloader.OpenSourceMergedSoMapping
import com.facebook.soloader.SoLoader

import expo.modules.ApplicationLifecycleDispatcher
import expo.modules.ReactNativeHostWrapper
import io.veil.mobile.crypto.VeilCryptoPackage
import io.veil.mobile.recovery.RecoveryActivity
import io.veil.mobile.recovery.VeilIdentitySetupPackage
import io.veil.mobile.runtime.VeilMobileRuntime
import io.veil.mobile.runtime.VeilMobileRuntimePackage

class MainApplication : Application(), ReactApplication, Application.ActivityLifecycleCallbacks {
  private val mainHandler = Handler(Looper.getMainLooper())
  private val activityVisibilityGate = AppActivityVisibilityGate(
    scheduleBackground = { operation -> mainHandler.post(operation) },
    cancelBackground = { operation -> mainHandler.removeCallbacks(operation) },
    onForeground = { veilMobileRuntime.markForeground() },
    onBackground = { veilMobileRuntime.lockForBackground() },
  )

  internal val veilMobileRuntime: VeilMobileRuntime by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
    VeilMobileRuntime(this)
  }

  override val reactNativeHost: ReactNativeHost = ReactNativeHostWrapper(
        this,
        object : DefaultReactNativeHost(this) {
          override fun getPackages(): List<ReactPackage> {
            val packages = PackageList(this).packages
            packages.add(VeilCryptoPackage())
            packages.add(VeilIdentitySetupPackage())
            packages.add(VeilMobileRuntimePackage(this@MainApplication.veilMobileRuntime))
            return packages
          }

          override fun getJSMainModuleName(): String = ".expo/.virtual-metro-entry"

          override fun getUseDeveloperSupport(): Boolean = BuildConfig.DEBUG

          override val isNewArchEnabled: Boolean = BuildConfig.IS_NEW_ARCHITECTURE_ENABLED
          override val isHermesEnabled: Boolean = BuildConfig.IS_HERMES_ENABLED
      }
  )

  override val reactHost: ReactHost
    get() = ReactNativeHostWrapper.createReactHost(applicationContext, reactNativeHost)

  override fun onCreate() {
    super.onCreate()
    registerActivityLifecycleCallbacks(this)
    SoLoader.init(this, OpenSourceMergedSoMapping)
    if (BuildConfig.IS_NEW_ARCHITECTURE_ENABLED) {
      // If you opted-in for the New Architecture, we load the native entry point for this app.
      load()
    }
    ApplicationLifecycleDispatcher.onApplicationCreate(this)
  }

  override fun onActivityStarted(activity: Activity) {
    activityVisibilityGate.onActivityStarted(activity.isTrustedVeilSurface())
  }

  override fun onActivityStopped(activity: Activity) {
    activityVisibilityGate.onActivityStopped(
      isTrustedSurface = activity.isTrustedVeilSurface(),
      isChangingConfigurations = activity.isChangingConfigurations,
    )
  }

  /**
   * Admit an ACTION_VIEW enrollment as a foreground-bound capability before
   * its secret fragment is parsed. Android may deliver onNewIntent before the
   * matching onStart callback; the posted zero-Activity recheck closes the
   * capability again if that foreground transition never materializes.
   */
  internal fun prepareForEnrollmentIntent() {
    activityVisibilityGate.onForegroundIntent()
  }

  override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit

  override fun onActivityResumed(activity: Activity) = Unit

  override fun onActivityPaused(activity: Activity) = Unit

  override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

  override fun onActivityDestroyed(activity: Activity) = Unit

  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    ApplicationLifecycleDispatcher.onConfigurationChanged(this, newConfig)
  }

  private fun Activity.isTrustedVeilSurface(): Boolean =
    javaClass == MainActivity::class.java || javaClass == RecoveryActivity::class.java
}

/**
 * Process-visible Activity ownership for the native security runtime.
 *
 * A posted zero-Activity transition is rechecked before locking. This keeps a
 * MainActivity -> RecoveryActivity handoff foreground-owned even if Android
 * reports stop/start in the opposite order, while a real app background still
 * closes the session and pending enrollment capability on the next main-loop
 * turn.
 */
internal class AppActivityVisibilityGate(
  private val scheduleBackground: (Runnable) -> Unit,
  private val cancelBackground: (Runnable) -> Unit,
  private val onForeground: () -> Unit,
  private val onBackground: () -> Unit,
) {
  private var startedActivities = 0
  private val backgroundOperation = Runnable {
    if (startedActivities == 0) onBackground()
  }

  fun onActivityStarted(isTrustedSurface: Boolean = true) {
    if (!isTrustedSurface) return
    cancelBackground(backgroundOperation)
    val wasInvisible = startedActivities == 0
    startedActivities += 1
    if (wasInvisible) onForeground()
  }

  fun onActivityStopped(
    isTrustedSurface: Boolean = true,
    isChangingConfigurations: Boolean = false,
  ) {
    if (!isTrustedSurface) return
    if (startedActivities > 0) startedActivities -= 1
    if (startedActivities == 0 && !isChangingConfigurations) {
      scheduleBackground(backgroundOperation)
    }
  }

  fun onForegroundIntent() {
    cancelBackground(backgroundOperation)
    // This callback is synchronous: callers must not stage the Pass until the
    // runtime has crossed the foreground barrier. If Android never starts an
    // Activity, the main-loop recheck restores the fail-closed background.
    onForeground()
    if (startedActivities == 0) scheduleBackground(backgroundOperation)
  }
}
