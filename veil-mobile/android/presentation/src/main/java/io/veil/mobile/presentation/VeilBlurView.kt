package io.veil.mobile.presentation

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ValueAnimator
import android.graphics.RenderEffect
import android.graphics.Shader
import android.os.Build
import com.facebook.react.uimanager.ThemedReactContext
import com.facebook.react.uimanager.annotations.ReactProp
import com.facebook.react.views.view.ReactViewGroup
import com.facebook.react.views.view.ReactViewManager

/** Live subtree blur, animated on Android's frame clock. No capture, bitmap or I/O. */
class VeilBlurView(context: ThemedReactContext) : ReactViewGroup(context) {
  var requestedRadius = 0f
  var transitionMs = 0
  private var targetRadius = -1f
  private var targetDuration = -1
  private var currentRadius = 0f
  private var appliedRadius = -1f
  private var effect: RenderEffect? = null
  private var animator: ValueAnimator? = null

  fun commitBlur() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
    val radius = requestedRadius * resources.displayMetrics.density
    if (radius != targetRadius || transitionMs != targetDuration) {
      stopAnimator()
      targetRadius = radius
      targetDuration = transitionMs
      if (transitionMs == 0 || !ValueAnimator.areAnimatorsEnabled() || currentRadius == radius) {
        currentRadius = radius
      } else {
        val next = ValueAnimator.ofFloat(currentRadius, radius)
        animator = next
        next.duration = transitionMs.toLong()
        next.addUpdateListener {
          currentRadius = it.animatedValue as Float
          applyCurrentEffect()
        }
        next.addListener(object : AnimatorListenerAdapter() {
          override fun onAnimationEnd(animation: Animator) {
            if (animator === animation) animator = null
            next.removeAllUpdateListeners()
            next.removeAllListeners()
          }
        })
        next.start()
      }
    }
    // BaseViewManager clears RenderEffect during every inherited transaction.
    // Restore the current frame, without restarting an in-flight transition.
    applyCurrentEffect()
  }

  private fun applyCurrentEffect() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
    if (currentRadius != appliedRadius) {
      appliedRadius = currentRadius
      effect = if (currentRadius <= 0f) null else
        RenderEffect.createBlurEffect(currentRadius, currentRadius, Shader.TileMode.CLAMP)
    }
    setRenderEffect(effect)
  }

  private fun stopAnimator() {
    animator?.let {
      it.removeAllUpdateListeners()
      it.removeAllListeners()
      it.cancel()
    }
    animator = null
  }

  override fun onDetachedFromWindow() {
    stopAnimator()
    // A detached view must neither retain a frame callback nor resume halfway.
    currentRadius = requestedRadius * resources.displayMetrics.density
    applyCurrentEffect()
    super.onDetachedFromWindow()
  }

  fun disposeBlur() {
    stopAnimator()
    requestedRadius = 0f
    currentRadius = 0f
    targetRadius = 0f
    effect = null
    appliedRadius = 0f
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) setRenderEffect(null)
  }
}

class VeilBlurViewManager : ReactViewManager() {
  override fun getName() = "VeilLiveBlurView"
  override fun createViewInstance(context: ThemedReactContext) = VeilBlurView(context)
  @ReactProp(name = "blurRadius", defaultFloat = 0f)
  fun setBlurRadius(view: ReactViewGroup, radius: Float) {
    (view as VeilBlurView).requestedRadius = if (radius.isFinite()) radius.coerceIn(0f, 32f) else 0f
  }
  @ReactProp(name = "blurTransitionMs", defaultInt = 0)
  fun setBlurTransitionMs(view: ReactViewGroup, duration: Int) {
    (view as VeilBlurView).transitionMs = duration.coerceIn(0, 1000)
  }
  override fun onAfterUpdateTransaction(view: ReactViewGroup) {
    super.onAfterUpdateTransaction(view)
    (view as VeilBlurView).commitBlur()
  }
  override fun onDropViewInstance(view: ReactViewGroup) {
    (view as VeilBlurView).disposeBlur()
    super.onDropViewInstance(view)
  }
}
