package io.veil.mobile.recovery

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.view.View
import io.veil.mobile.R

/** Code-native rendering of assets/brand/phase-shift-mark.svg. */
internal class PhaseShiftMarkView(context: Context) : View(context) {
  private val backgroundPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = Color.rgb(0x0d, 0x0e, 0x14)
    style = Paint.Style.FILL
  }
  private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = Color.rgb(0x2e, 0x2e, 0x50)
    style = Paint.Style.STROKE
    strokeWidth = 1f
  }
  private val markPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    color = Color.rgb(0xa7, 0x8b, 0xfa)
    style = Paint.Style.FILL
  }
  private val frame = RectF(0.5f, 0.5f, 23.5f, 23.5f)
  private val mark = Path().apply {
    polygon(4f, 4f, 8f, 4f, 8f, 11.8f, 4f, 13f)
    polygon(4f, 16f, 8f, 14.8f, 8f, 20f, 4f, 20f)
    polygon(10f, 2f, 14f, 2f, 14f, 10.5f, 10f, 11.7f)
    polygon(10f, 14.7f, 14f, 13.5f, 14f, 22f, 10f, 22f)
    polygon(16f, 5f, 20f, 5f, 20f, 8.2f, 16f, 9.4f)
    polygon(16f, 12.4f, 20f, 11.2f, 20f, 19f, 16f, 19f)
  }

  init {
    contentDescription = context.getString(R.string.app_name)
    isSaveEnabled = false
    importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_YES
  }

  override fun onDraw(canvas: Canvas) {
    super.onDraw(canvas)
    val scale = minOf(width, height) / 24f
    val x = (width - 24f * scale) / 2f
    val y = (height - 24f * scale) / 2f
    canvas.save()
    canvas.translate(x, y)
    canvas.scale(scale, scale)
    canvas.drawRoundRect(frame, 5.5f, 5.5f, backgroundPaint)
    canvas.drawRoundRect(frame, 5.5f, 5.5f, borderPaint)
    canvas.drawPath(mark, markPaint)
    canvas.restore()
  }

  private fun Path.polygon(vararg points: Float) {
    require(points.size >= 6 && points.size % 2 == 0)
    moveTo(points[0], points[1])
    var offset = 2
    while (offset < points.size) {
      lineTo(points[offset], points[offset + 1])
      offset += 2
    }
    close()
  }
}
