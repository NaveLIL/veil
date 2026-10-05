package io.veil.mobile.presentation

import android.app.Activity
import android.content.Intent
import android.content.res.AssetFileDescriptor
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import android.os.CancellationSignal
import com.facebook.react.bridge.ActivityEventListener
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.UiThreadUtil
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.lang.ref.WeakReference
import java.util.concurrent.Future
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * An explicit document choice is copied once into a bounded, metadata-free
 * preview cache image. Provider URIs and their grants never cross the bridge.
 * No gallery enumeration, persisted grant, preferences or Veil identity exists.
 */
open class AppearancePickerModule(context: ReactApplicationContext, private val moduleName: String = "VeilAppearance") :
  ReactContextBaseJavaModule(context), ActivityEventListener {
  private class Pick(val requestCode: Int, val promise: Promise) {
    var activity: WeakReference<Activity>? = null
    var processing = false
    var input: InputStream? = null
    var descriptor: AssetFileDescriptor? = null
    var future: Future<*>? = null
    var deadline: Future<*>? = null
    val cancellation = CancellationSignal()
  }

  private val lock = Any()
  // Two bounded slots allow recovery from one provider which ignores close /
  // cancellation. No work queue or unlimited replacement threads can grow.
  private val worker = ThreadPoolExecutor(0, 2, 30L, TimeUnit.SECONDS,
    SynchronousQueue(), { task ->
      Thread(task, "veil-design-wallpaper").apply { isDaemon = true }
    })
  // A provider may block even its cancel / close callbacks. Keep those calls
  // off the UI and sole deadline thread, with the same strict thread bound.
  private val cleanup = ThreadPoolExecutor(0, 2, 30L, TimeUnit.SECONDS,
    SynchronousQueue(), { task ->
      Thread(task, "veil-design-wallpaper-cleanup").apply { isDaemon = true }
    })
  private val deadlines = ScheduledThreadPoolExecutor(1) { task ->
    Thread(task, "veil-design-wallpaper-deadline").apply { isDaemon = true }
  }.apply { removeOnCancelPolicy = true }
  private val ownedFiles = mutableSetOf<File>()
  private val publishedFiles = java.util.ArrayDeque<File>()
  private var pending: Pick? = null
  private var invalidated = false
  private var nextRequestCode = FIRST_REQUEST_CODE

  init {
    context.addActivityEventListener(this)
    // The selection is intentionally session-only. Clean only this module's
    // own flat cache names left by an interrupted process, never other files.
    context.cacheDir.listFiles { _, name -> CACHE_NAME.matches(name) }?.forEach { it.delete() }
  }

  override fun getName(): String = moduleName

  @ReactMethod
  open fun pickWallpaper(promise: Promise) {
    val pick = synchronized(lock) {
      when {
        invalidated || nextRequestCode > LAST_REQUEST_CODE -> {
          reject(promise, UNAVAILABLE_CODE)
          null
        }
        pending != null -> {
          reject(promise, BUSY_CODE)
          null
        }
        else -> Pick(nextRequestCode++, promise).also { pending = it }
      }
    } ?: return
    UiThreadUtil.runOnUiThread {
      val activity = currentActivity
      if (activity == null || activity.isFinishing || activity.isDestroyed ||
        !activity.hasWindowFocus()) {
        fail(pick)
        return@runOnUiThread
      }
      try {
        synchronized(lock) {
          if (invalidated || pending !== pick) return@runOnUiThread
          pick.activity = WeakReference(activity)
          activity.startActivityForResult(
            Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
              addCategory(Intent.CATEGORY_OPENABLE)
              type = "image/*"
              putExtra(Intent.EXTRA_ALLOW_MULTIPLE, false)
              addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            },
            pick.requestCode,
          )
        }
      } catch (_: Throwable) {
        fail(pick)
      }
    }
  }

  override fun onActivityResult(activity: Activity, requestCode: Int, resultCode: Int,
    data: Intent?) {
    val pick = synchronized(lock) {
      pending?.takeIf { !invalidated && it.requestCode == requestCode && !it.processing }
    } ?: return
    if (pick.activity?.get() !== activity || currentActivity !== activity ||
      activity.isFinishing || activity.isDestroyed) {
      fail(pick)
      return
    }
    if (resultCode == Activity.RESULT_CANCELED) {
      finish(pick, null)
      return
    }
    val uri = data?.data
    val clip = data?.clipData
    if (resultCode != Activity.RESULT_OK || uri == null || uri.scheme != "content" ||
      !uri.isHierarchical || uri.authority.isNullOrBlank() || uri.fragment != null ||
      (clip != null && (clip.itemCount != 1 || clip.getItemAt(0).uri != uri))) {
      fail(pick)
      return
    }
    try {
      synchronized(lock) {
        if (invalidated || pending !== pick) return
        pick.processing = true
        pick.deadline = deadlines.schedule({ abort(pick) }, IMPORT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        pick.future = worker.submit { importSelectedImage(pick, uri) }
      }
    } catch (_: Throwable) {
      fail(pick)
    }
  }

  override fun onNewIntent(intent: Intent) = Unit

  private fun importSelectedImage(pick: Pick, uri: Uri) {
    var encoded: ByteArray? = null
    var bitmap: Bitmap? = null
    var output: File? = null
    var published = false
    try {
      ensureCurrent(pick)
      val descriptor = reactApplicationContext.contentResolver.openAssetFileDescriptor(
        uri, "r", pick.cancellation)
        ?: throw IllegalStateException()
      val descriptorAccepted = synchronized(lock) {
        if (invalidated || pending !== pick) false else {
          pick.descriptor = descriptor
          true
        }
      }
      if (!descriptorAccepted) {
        descriptor.close()
        throw IllegalStateException()
      }
      val bytes = descriptor.use {
        val input = it.createInputStream()
        val inputAccepted = synchronized(lock) {
          if (invalidated || pending !== pick) false else {
            pick.input = input
            true
          }
        }
        if (!inputAccepted) {
          input.close()
          throw IllegalStateException()
        }
        input.use { stream -> readBounded(pick, stream) }
      }
      encoded = bytes
      synchronized(lock) { pick.input = null; pick.descriptor = null }
      ensureCurrent(pick)
      val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
      BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
      val width = bounds.outWidth
      val height = bounds.outHeight
      if (width !in 1..MAX_SOURCE_DIMENSION || height !in 1..MAX_SOURCE_DIMENSION ||
        width.toLong() * height.toLong() > MAX_SOURCE_PIXELS) throw IllegalStateException()
      var sample = 1
      while ((maxOf(width, height) + sample - 1) / sample > MAX_OUTPUT_EDGE) sample *= 2
      val options = BitmapFactory.Options().apply {
        inSampleSize = sample
        inPreferredConfig = Bitmap.Config.ARGB_8888
        inScaled = false
        inDensity = 0
        inTargetDensity = 0
      }
      bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
        ?: throw IllegalStateException()
      ensureCurrent(pick)
      if (bitmap.width !in 1..MAX_DECODED_EDGE || bitmap.height !in 1..MAX_DECODED_EDGE ||
        bitmap.width.toLong() * bitmap.height.toLong() > MAX_DECODED_PIXELS) {
        throw IllegalStateException()
      }
      if (maxOf(bitmap.width, bitmap.height) > MAX_OUTPUT_EDGE) {
        val ratio = MAX_OUTPUT_EDGE.toDouble() / maxOf(bitmap.width, bitmap.height)
        val scaled = Bitmap.createScaledBitmap(bitmap,
          maxOf(1, (bitmap.width * ratio).toInt()),
          maxOf(1, (bitmap.height * ratio).toInt()), true)
        if (scaled !== bitmap) bitmap.recycle()
        bitmap = scaled
      }
      val orientation = try {
        ExifInterface(ByteArrayInputStream(bytes)).getAttributeInt(
          ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
      } catch (_: Exception) {
        ExifInterface.ORIENTATION_NORMAL
      }
      val matrix = orientationMatrix(orientation)
      if (matrix != null) {
        val oriented = Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
        if (oriented !== bitmap) bitmap.recycle()
        bitmap = oriented
      }
      ensureCurrent(pick)
      val readyBitmap = checkNotNull(bitmap)
      check(readyBitmap.width <= MAX_OUTPUT_EDGE && readyBitmap.height <= MAX_OUTPUT_EDGE)
      val cacheFile = File.createTempFile(CACHE_PREFIX, ".jpg", reactApplicationContext.cacheDir)
      output = cacheFile
      synchronized(lock) { ownedFiles.add(cacheFile) }
      FileOutputStream(cacheFile).use { stream ->
        check(readyBitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, stream))
      }
      check(cacheFile.length() in 1L..MAX_ENCODED_BYTES.toLong())
      published = finish(pick, Uri.fromFile(cacheFile).toString(), cacheFile)
    } catch (_: Throwable) {
      fail(pick)
    } finally {
      synchronized(lock) { pick.input = null; pick.descriptor = null }
      encoded?.fill(0)
      bitmap?.recycle()
      if (!published) output?.let { file ->
        file.delete()
        synchronized(lock) { ownedFiles.remove(file) }
      }
    }
  }

  private fun readBounded(pick: Pick, input: InputStream): ByteArray {
    val buffer = ByteArray(64 * 1024)
    val bytes = ByteArrayOutputStream(buffer.size)
    try {
      while (true) {
        ensureCurrent(pick)
        val count = input.read(buffer, 0, minOf(buffer.size, MAX_ENCODED_BYTES - bytes.size() + 1))
        if (count == -1) break
        // Positive-length InputStream reads must make progress.
        if (count <= 0 || count > MAX_ENCODED_BYTES - bytes.size()) throw IllegalStateException()
        bytes.write(buffer, 0, count)
      }
      check(bytes.size() > 0)
      return bytes.toByteArray()
    } finally {
      buffer.fill(0)
      bytes.close()
    }
  }

  private fun ensureCurrent(pick: Pick) {
    synchronized(lock) { check(!invalidated && pending === pick) }
    check(!Thread.currentThread().isInterrupted)
  }

  private fun finish(pick: Pick, uri: String?, file: File? = null): Boolean = synchronized(lock) {
    if (invalidated || pending !== pick) return@synchronized false
    pending = null
    pick.deadline?.cancel(false)
    if (file != null) {
      publishedFiles.addLast(file)
      // Keep one predecessor during the UI image-source handover, bounded to
      // two published JPEGs rather than retaining every chosen photograph.
      while (publishedFiles.size > MAX_PUBLISHED_FILES) {
        val old = publishedFiles.removeFirst()
        old.delete()
        ownedFiles.remove(old)
      }
    }
    pick.promise.resolve(uri)
    true
  }

  private fun fail(pick: Pick) {
    synchronized(lock) {
      if (pending !== pick) return
      pending = null
      pick.deadline?.cancel(false)
      reject(pick.promise, UNAVAILABLE_CODE)
    }
  }

  private fun abort(pick: Pick) {
    val shouldClose = synchronized(lock) {
      if (pending !== pick) false else {
        pending = null
        reject(pick.promise, UNAVAILABLE_CODE)
        true
      }
    }
    if (!shouldClose) return
    pick.future?.cancel(true)
    closeProviderAsync(pick)
  }

  private fun closeProviderAsync(pick: Pick) {
    val captured = synchronized(lock) { Pair(pick.input, pick.descriptor) }
    try {
      cleanup.execute {
        try { pick.cancellation.cancel() } catch (_: Throwable) { /* No provider diagnostics. */ }
        try { captured.first?.close() } catch (_: Throwable) { /* No provider diagnostics. */ }
        try { captured.second?.close() } catch (_: Throwable) { /* No provider diagnostics. */ }
      }
    } catch (_: Throwable) {
      // Both cleanup slots may be held by broken providers. Never run their
      // callbacks synchronously or grow an unbounded thread / work queue.
    }
  }

  override fun invalidate() {
    val stale = synchronized(lock) {
      invalidated = true
      pending.also { pending = null }
    }
    stale?.deadline?.cancel(false)
    stale?.future?.cancel(true)
    stale?.let {
      reject(it.promise, UNAVAILABLE_CODE)
      closeProviderAsync(it)
    }
    worker.shutdownNow()
    deadlines.shutdownNow()
    cleanup.shutdown()
    synchronized(lock) {
      ownedFiles.forEach { it.delete() }
      ownedFiles.clear()
      publishedFiles.clear()
    }
    reactApplicationContext.removeActivityEventListener(this)
    super.invalidate()
  }

  private fun reject(promise: Promise, code: String) {
    promise.reject(code, "Local wallpaper selection is unavailable")
  }

  companion object {
    private const val FIRST_REQUEST_CODE = 0x5200
    private const val LAST_REQUEST_CODE = 0x7fff
    private const val MAX_ENCODED_BYTES = 16 * 1024 * 1024
    private const val MAX_SOURCE_DIMENSION = 32_768
    private const val MAX_SOURCE_PIXELS = 64_000_000L
    private const val MAX_OUTPUT_EDGE = 2048
    private const val MAX_DECODED_EDGE = 4096
    private const val MAX_DECODED_PIXELS = 16_777_216L
    private const val JPEG_QUALITY = 88
    private const val IMPORT_TIMEOUT_SECONDS = 30L
    private const val MAX_PUBLISHED_FILES = 2
    private const val CACHE_PREFIX = "veil-design-wallpaper-"
    private val CACHE_NAME = Regex("veil-design-wallpaper-[A-Za-z0-9_-]{1,96}\\.jpg")
    private const val UNAVAILABLE_CODE = "E_VEIL_DESIGN_APPEARANCE"
    private const val BUSY_CODE = "E_VEIL_DESIGN_APPEARANCE_BUSY"
  }

  private fun orientationMatrix(orientation: Int): Matrix? = when (orientation) {
    ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> Matrix().apply { setScale(-1f, 1f) }
    ExifInterface.ORIENTATION_ROTATE_180 -> Matrix().apply { setRotate(180f) }
    ExifInterface.ORIENTATION_FLIP_VERTICAL -> Matrix().apply { setScale(1f, -1f) }
    ExifInterface.ORIENTATION_TRANSPOSE -> Matrix().apply { setRotate(90f); postScale(-1f, 1f) }
    ExifInterface.ORIENTATION_ROTATE_90 -> Matrix().apply { setRotate(90f) }
    ExifInterface.ORIENTATION_TRANSVERSE -> Matrix().apply { setRotate(-90f); postScale(-1f, 1f) }
    ExifInterface.ORIENTATION_ROTATE_270 -> Matrix().apply { setRotate(-90f) }
    else -> null
  }
}
