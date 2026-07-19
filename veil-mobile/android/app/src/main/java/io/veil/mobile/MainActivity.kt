package io.veil.mobile

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager

import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.fabricEnabled
import com.facebook.react.defaults.DefaultReactActivityDelegate

import expo.modules.ReactActivityDelegateWrapper

class MainActivity : ReactActivity() {
  private val readyScreenCaptureGate = ReadyScreenCaptureGate()

  @Volatile
  private var publishedReadyScreenCaptureGeneration = 0L

  override fun onCreate(savedInstanceState: Bundle?) {
    revokeReadyScreenCaptureEligibility()
    // Set the theme to AppTheme BEFORE onCreate to support
    // coloring the background, status bar, and navigation bar.
    // This is required for expo-splash-screen.
    setTheme(R.style.AppTheme);
    // Closed preview policy: never allow Android screenshots, non-secure
    // displays, or an unredacted task snapshot to capture account plaintext.
    // A future user-facing screenshot preference must preserve recovery and
    // task-switcher protection as separate non-optional boundaries.
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    // No enrollment capability is parsed until the receiving window is
    // non-capturable, including the process' first Activity launch.
    consumeEnrollmentIntent(intent)
    super.onCreate(null)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      setRecentsScreenshotEnabled(false)
    }
  }

  override fun onNewIntent(intent: Intent) {
    revokeReadyScreenCaptureEligibility()
    // Enrollment must become non-capturable before any new capability is
    // consumed or reflected into the React runtime.
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    consumeEnrollmentIntent(intent)
    super.onNewIntent(intent)
    setIntent(intent)
  }

  override fun onResume() {
    super.onResume()
    publishedReadyScreenCaptureGeneration = readyScreenCaptureGate.grantForeground()
  }

  override fun onPause() {
    revokeReadyScreenCaptureEligibility()
    // Re-apply before Android is allowed to snapshot or background the task.
    // A ready debug shell may explicitly clear this again after foreground
    // runtime verification; Recents itself remains permanently disabled.
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    super.onPause()
  }

  internal fun captureReadyScreenCaptureGeneration(): Long =
    publishedReadyScreenCaptureGeneration

  /** Must be called on the Activity main thread. */
  internal fun acceptsReadyScreenCaptureGeneration(expectedGeneration: Long): Boolean =
    readyScreenCaptureGate.accepts(expectedGeneration)

  private fun revokeReadyScreenCaptureEligibility() {
    publishedReadyScreenCaptureGeneration = readyScreenCaptureGate.revoke()
  }

  /**
   * Enrollment capabilities are consumed before ReactActivity/Linking sees the
   * Intent. Only a sanitized runtime snapshot is ever published to JavaScript.
   */
  private fun consumeEnrollmentIntent(intent: Intent?) {
    if (intent?.action != Intent.ACTION_VIEW) return
    val raw = intent.dataString ?: return
    val app = application as MainApplication
    // Android may invoke onNewIntent before onStart. Cross the native
    // foreground barrier first so a stale AppState lock cannot erase the new
    // Pass between parsing and the Activity lifecycle callback.
    app.prepareForEnrollmentIntent()
    if (!app.veilMobileRuntime.consumeEnrollmentUri(raw)) return
    intent.data = null
    intent.clipData = null
    intent.selector = null
    intent.replaceExtras(Bundle())
  }

  /**
   * Returns the name of the main component registered from JavaScript. This is used to schedule
   * rendering of the component.
   */
  override fun getMainComponentName(): String = "main"

  /**
   * Returns the instance of the [ReactActivityDelegate]. We use [DefaultReactActivityDelegate]
   * which allows you to enable New Architecture with a single boolean flags [fabricEnabled]
   */
  override fun createReactActivityDelegate(): ReactActivityDelegate {
    return ReactActivityDelegateWrapper(
          this,
          BuildConfig.IS_NEW_ARCHITECTURE_ENABLED,
          object : DefaultReactActivityDelegate(
              this,
              mainComponentName,
              fabricEnabled
          ){})
  }

  /**
    * Align the back button behavior with Android S
    * where moving root activities to background instead of finishing activities.
    * @see <a href="https://developer.android.com/reference/android/app/Activity#onBackPressed()">onBackPressed</a>
    */
  override fun invokeDefaultOnBackPressed() {
      if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
          if (!moveTaskToBack(false)) {
              // For non-root activities, use the default implementation to finish them.
              super.invokeDefaultOnBackPressed()
          }
          return
      }

      // Use the default back button implementation on Android S
      // because it's doing more than [Activity.moveTaskToBack] in fact.
      super.invokeDefaultOnBackPressed()
  }
}

/**
 * Main-thread state machine for the debug-only Ready capture exception.
 *
 * A generation is invalidated before every sensitive/background transition and
 * a fresh generation is granted only after the Activity resumes. A clear
 * request posted before a transition therefore cannot become valid again after
 * a later resume.
 */
internal class ReadyScreenCaptureGate {
  private var generation = 0L
  private var foregroundEligible = false

  fun revoke(): Long {
    foregroundEligible = false
    generation += 1
    return generation
  }

  fun grantForeground(): Long {
    foregroundEligible = true
    generation += 1
    return generation
  }

  fun accepts(expectedGeneration: Long): Boolean =
    foregroundEligible && expectedGeneration == generation
}
