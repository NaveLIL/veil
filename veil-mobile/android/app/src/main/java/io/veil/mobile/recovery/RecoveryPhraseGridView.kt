package io.veil.mobile.recovery

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.os.Build
import android.util.TypedValue
import android.view.View
import io.veil.mobile.R
import kotlin.math.ceil
import kotlin.math.max

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
  ownedIndices: IntArray,
) : View(context) {
  private val indices = ownedIndices
  private val surfacePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = context.colorCompat(R.color.recoverySurfaceLow)
  }
  private val cellPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = context.colorCompat(R.color.recoverySurfaceRaised)
  }
  private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = context.colorCompat(R.color.recoveryBorder)
    style = Paint.Style.STROKE
    strokeWidth = dp(1).toFloat()
  }
  private val positionPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = context.colorCompat(R.color.recoveryTextMuted)
    textSize = sp(11f)
    typeface = android.graphics.Typeface.create("monospace", android.graphics.Typeface.NORMAL)
  }
  private val wordPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = context.colorCompat(R.color.recoveryText)
    textSize = sp(14f)
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
    val desiredHeight = paddingTop + paddingBottom + rows * cellHeight()
    setMeasuredDimension(width, resolveSize(desiredHeight, heightMeasureSpec))
  }

  override fun onDraw(canvas: Canvas) {
    super.onDraw(canvas)
    if (wiped) return

    bounds.set(0f, 0f, width.toFloat(), height.toFloat())
    canvas.drawRoundRect(bounds, dp(16).toFloat(), dp(16).toFloat(), surfacePaint)
    canvas.drawRoundRect(bounds, dp(16).toFloat(), dp(16).toFloat(), borderPaint)
    val columns = columnsFor(width)
    val cellHeight = cellHeight()
    val cellWidth = (width - paddingLeft - paddingRight).toFloat() / columns
    val fontMetrics = wordPaint.fontMetrics
    val baselineOffset = (cellHeight - fontMetrics.ascent - fontMetrics.descent) / 2f
    val positionLabelWidth = positionLabelWidth()

    for (position in indices.indices) {
      val row = position / columns
      val column = position % columns
      val cellLeft = paddingLeft + column * cellWidth + dp(4)
      val cellTop = paddingTop + row * cellHeight + dp(4)
      val cellRight = paddingLeft + (column + 1) * cellWidth - dp(4)
      val cellBottom = paddingTop + (row + 1) * cellHeight - dp(4)
      canvas.drawRoundRect(
        cellLeft,
        cellTop.toFloat(),
        cellRight,
        cellBottom.toFloat(),
        dp(10).toFloat(),
        dp(10).toFloat(),
        cellPaint,
      )
      val left = cellLeft + dp(10)
      val baseline = paddingTop + row * cellHeight + baselineOffset
      canvas.drawText(POSITION_LABELS[position], left, baseline, positionPaint)

      val wordIndex = indices[position]
      if (wordIndex >= 0) {
        canvas.drawText(
          dictionary.word(wordIndex),
          left + positionLabelWidth,
          baseline,
          wordPaint,
        )
      } else {
        canvas.drawText(UNSET_LABEL, left + positionLabelWidth, baseline, wordPaint)
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

  private fun columnsFor(availableWidth: Int): Int = when {
    resources.configuration.fontScale >= LARGE_FONT_SCALE -> 1
    availableWidth >= dp(THREE_COLUMN_MIN_WIDTH_DP) -> 3
    else -> 2
  }

  private fun cellHeight(): Int {
    val tallestText = max(
      positionPaint.fontMetrics.descent - positionPaint.fontMetrics.ascent,
      wordPaint.fontMetrics.descent - wordPaint.fontMetrics.ascent,
    )
    return max(dp(CELL_HEIGHT_DP), ceil(tallestText).toInt() + dp(CELL_VERTICAL_PADDING_DP))
  }

  private fun positionLabelWidth(): Float = max(
    dp(POSITION_LABEL_WIDTH_DP).toFloat(),
    positionPaint.measureText(POSITION_LABELS.last()) + dp(POSITION_LABEL_GAP_DP),
  )

  private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

  private fun sp(value: Float): Float =
    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, value, resources.displayMetrics)

  companion object {
    private const val CELL_HEIGHT_DP = 50
    private const val CELL_VERTICAL_PADDING_DP = 20
    private const val THREE_COLUMN_MIN_WIDTH_DP = 420
    private const val LARGE_FONT_SCALE = 1.5f
    private const val POSITION_LABEL_WIDTH_DP = 30
    private const val POSITION_LABEL_GAP_DP = 8
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
