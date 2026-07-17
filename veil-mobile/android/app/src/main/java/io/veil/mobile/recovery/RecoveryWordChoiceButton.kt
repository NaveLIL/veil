package io.veil.mobile.recovery

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.os.Build
import android.util.TypedValue
import android.view.View
import android.view.ViewStructure

/** A word-choice control whose selected scalar can be overwritten on detach. */
internal class RecoveryWordChoiceButton(
  context: Context,
  word: String,
  wordIndex: Int,
  private var onChosen: ((Int) -> Unit)?,
) : View(context) {
  private var publicWord = word
  private var mutableWordIndex = wordIndex
  private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = Color.rgb(0xf4, 0xf8, 0xfc)
    textSize = TypedValue.applyDimension(
      TypedValue.COMPLEX_UNIT_SP,
      15f,
      resources.displayMetrics,
    )
    textAlign = Paint.Align.CENTER
    typeface = android.graphics.Typeface.create(
      android.graphics.Typeface.DEFAULT,
      android.graphics.Typeface.BOLD,
    )
  }
  private val backgroundPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = Color.rgb(0x18, 0x32, 0x49)
  }

  init {
    isClickable = true
    isFocusable = true
    isSaveEnabled = false
    isLongClickable = false
    filterTouchesWhenObscured = true
    importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      importantForAutofill = IMPORTANT_FOR_AUTOFILL_NO
    }
    RecoveryContentCapture.exclude(this)
    minimumHeight = dp(48)
    setOnClickListener {
      val selected = mutableWordIndex
      if (selected >= 0) onChosen?.invoke(selected)
    }
  }

  override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
    setMeasuredDimension(
      resolveSize(suggestedMinimumWidth, widthMeasureSpec),
      resolveSize(dp(48), heightMeasureSpec),
    )
  }

  override fun onDraw(canvas: Canvas) {
    super.onDraw(canvas)
    backgroundPaint.color =
      if (isPressed || isFocused) Color.rgb(0x23, 0x48, 0x65) else Color.rgb(0x18, 0x32, 0x49)
    canvas.drawRoundRect(
      0f,
      0f,
      width.toFloat(),
      height.toFloat(),
      dp(12).toFloat(),
      dp(12).toFloat(),
      backgroundPaint,
    )
    val baseline = (height - paint.fontMetrics.ascent - paint.fontMetrics.descent) / 2f
    canvas.drawText(publicWord, width / 2f, baseline, paint)
  }

  override fun drawableStateChanged() {
    super.drawableStateChanged()
    invalidate()
  }

  override fun dispatchProvideStructure(structure: ViewStructure) {
    structure.setChildCount(0)
    structure.setText("")
  }

  override fun onProvideAutofillStructure(structure: ViewStructure, flags: Int) {
    structure.setChildCount(0)
    structure.setText("")
  }

  fun wipe() {
    mutableWordIndex = -1
    publicWord = ""
    onChosen = null
    setOnClickListener(null)
    invalidate()
  }

  override fun onDetachedFromWindow() {
    wipe()
    super.onDetachedFromWindow()
  }

  private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
