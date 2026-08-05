package io.veil.mobile.recovery

import android.app.Activity
import android.os.Build
import android.view.View

/** API-isolated ContentCapture defenses for the API 24 runtime floor. */
internal object RecoveryContentCapture {
  fun disableForActivity(activity: Activity) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      Api29ContentCapture.disableManager(activity)
    }
    exclude(activity.window.decorView, hideDescendants = true)
  }

  fun exclude(view: View, hideDescendants: Boolean = false) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      Api30ContentCapture.exclude(view, hideDescendants)
    }
  }
}

@android.annotation.TargetApi(Build.VERSION_CODES.Q)
private object Api29ContentCapture {
  fun disableManager(activity: Activity) {
    activity.getSystemService(android.view.contentcapture.ContentCaptureManager::class.java)
      ?.setContentCaptureEnabled(false)
  }
}

@android.annotation.TargetApi(Build.VERSION_CODES.R)
private object Api30ContentCapture {
  fun exclude(view: View, hideDescendants: Boolean) {
    view.importantForContentCapture =
      if (hideDescendants) {
        View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
      } else {
        View.IMPORTANT_FOR_CONTENT_CAPTURE_NO
      }
  }
}
