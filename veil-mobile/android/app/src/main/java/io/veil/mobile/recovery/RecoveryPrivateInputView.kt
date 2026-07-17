package io.veil.mobile.recovery

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.os.Build
import android.util.TypedValue
import android.view.View
import android.view.ViewStructure

/** Mutable, Canvas-only recovery-word prefix; no TextView/IME/translation text. */
internal class RecoveryPrivateInputView(
  context: Context,
  source: CharArray,
) : View(context) {
  private val characters = CharArray(PinnedBip39EnglishWords.MAX_WORD_LENGTH)
  private var length = source.size
  private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = Color.rgb(0xf4, 0xf8, 0xfc)
    textSize = TypedValue.applyDimension(
      TypedValue.COMPLEX_UNIT_SP,
      22f,
      resources.displayMetrics,
    )
    typeface = android.graphics.Typeface.create("monospace", android.graphics.Typeface.NORMAL)
  }

  init {
    require(source.size <= characters.size)
    source.copyInto(characters)
    isSaveEnabled = false
    isClickable = false
    isLongClickable = false
    importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      importantForAutofill = IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }
    RecoveryContentCapture.exclude(this, hideDescendants = true)
    minimumHeight = dp(48)
  }

  override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
    setMeasuredDimension(
      resolveSize(suggestedMinimumWidth, widthMeasureSpec),
      resolveSize(dp(48), heightMeasureSpec),
    )
  }

  override fun onDraw(canvas: Canvas) {
    super.onDraw(canvas)
    val baseline = (height - paint.fontMetrics.ascent - paint.fontMetrics.descent) / 2f
    if (length == 0) {
      canvas.drawText(EMPTY_LABEL, 0f, baseline, paint)
    } else {
      canvas.drawText(characters, 0, length, 0f, baseline, paint)
    }
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
    characters.fill('\u0000')
    length = 0
    invalidate()
  }

  override fun onDetachedFromWindow() {
    wipe()
    super.onDetachedFromWindow()
  }

  private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

  companion object {
    private const val EMPTY_LABEL = "...."
  }
}
