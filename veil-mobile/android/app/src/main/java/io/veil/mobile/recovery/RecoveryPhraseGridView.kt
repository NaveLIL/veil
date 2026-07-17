package io.veil.mobile.recovery

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.os.Build
import android.util.TypedValue
import android.view.View
import io.veil.mobile.R

/**
 * Draws a recovery phrase without constructing a phrase-shaped JVM String.
 *
 * The view owns only a mutable copy of scalar indices. Position labels and
 * dictionary words are drawn in separate calls, so no immutable object ever
 * encodes the selected sequence. [wipe] overwrites the indices immediately.
 */
internal class RecoveryPhraseGridView(
  context: Context,
  private val dictionary: RecoveryWordDictionary,
  sourceIndices: IntArray,
) : View(context) {
  private val indices = sourceIndices.copyOf()
  private val surfacePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = context.colorCompat(R.color.recoverySurface)
  }
  private val positionPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = context.colorCompat(R.color.recoveryTextMuted)
    textSize = sp(12f)
    typeface = android.graphics.Typeface.create("monospace", android.graphics.Typeface.NORMAL)
  }
  private val wordPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = context.colorCompat(R.color.recoveryText)
    textSize = sp(15f)
    typeface = android.graphics.Typeface.create("monospace", android.graphics.Typeface.BOLD)
  }
  private val bounds = RectF()
  private var wiped = false

  init {
    isSaveEnabled = false
    isLongClickable = false
    isClickable = false
    filterTouchesWhenObscured = true
    importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      importantForAutofill = IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }
    RecoveryContentCapture.exclude(this, hideDescendants = true)
    minimumHeight = dp(64)
  }

  override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
    val width = resolveSize(suggestedMinimumWidth, widthMeasureSpec)
    val columns = columnsFor(width)
    val rows = (indices.size + columns - 1) / columns
    val desiredHeight = paddingTop + paddingBottom + rows * dp(CELL_HEIGHT_DP)
    setMeasuredDimension(width, resolveSize(desiredHeight, heightMeasureSpec))
  }

  override fun onDraw(canvas: Canvas) {
    super.onDraw(canvas)
    if (wiped) return

    bounds.set(0f, 0f, width.toFloat(), height.toFloat())
    canvas.drawRoundRect(bounds, dp(16).toFloat(), dp(16).toFloat(), surfacePaint)
    val columns = columnsFor(width)
    val cellWidth = (width - paddingLeft - paddingRight).toFloat() / columns
    val baselineOffset = dp(31).toFloat()

    for (position in indices.indices) {
      val row = position / columns
      val column = position % columns
      val left = paddingLeft + column * cellWidth + dp(10)
      val baseline = paddingTop + row * dp(CELL_HEIGHT_DP) + baselineOffset
      canvas.drawText(POSITION_LABELS[position], left, baseline, positionPaint)

      val wordIndex = indices[position]
      if (wordIndex >= 0) {
        canvas.drawText(
          dictionary.word(wordIndex),
          left + dp(POSITION_LABEL_WIDTH_DP),
          baseline,
          wordPaint,
        )
      } else {
        canvas.drawText(UNSET_LABEL, left + dp(POSITION_LABEL_WIDTH_DP), baseline, wordPaint)
      }
    }
  }

  fun wipe() {
    if (wiped) return
    indices.fill(UNSET_INDEX)
    wiped = true
    invalidate()
  }

  override fun onDetachedFromWindow() {
    wipe()
    super.onDetachedFromWindow()
  }

  private fun columnsFor(availableWidth: Int): Int = if (availableWidth >= dp(600)) 3 else 2

  private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

  private fun sp(value: Float): Float =
    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, value, resources.displayMetrics)

  companion object {
    private const val CELL_HEIGHT_DP = 52
    private const val POSITION_LABEL_WIDTH_DP = 30
    private const val UNSET_INDEX = -1
    private const val UNSET_LABEL = "\u2014"
    private val POSITION_LABELS = Array(24) { position -> (position + 1).toString() + "." }
  }
}

private fun Context.colorCompat(resource: Int): Int =
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
    getColor(resource)
  } else {
    @Suppress("DEPRECATION")
    resources.getColor(resource)
  }
