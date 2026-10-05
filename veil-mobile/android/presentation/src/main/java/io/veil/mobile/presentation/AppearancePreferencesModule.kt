package io.veil.mobile.presentation

import android.net.Uri
import android.graphics.BitmapFactory
import android.util.AtomicFile
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import org.json.JSONObject
import org.json.JSONException
import java.io.File
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Local public appearance settings. No account, content or secret input. */
open class AppearancePreferencesModule(context: ReactApplicationContext, private val moduleName: String = "VeilAppearancePreferences", folder: String = "appearance") : ReactContextBaseJavaModule(context) {
  private val dir = File(context.filesDir, folder)
  private val executor = ThreadPoolExecutor(1, 1, 0L, TimeUnit.SECONDS, ArrayBlockingQueue<Runnable>(2))
  private val settings get() = AtomicFile(File(dir, "settings.json"))
  override fun getName() = moduleName
  private fun run(promise: Promise, block: () -> Any?) {
    try { executor.execute {
      try { promise.resolve(block()) } catch (_: Throwable) { promise.reject("E_DESIGN_PREFERENCES", "Local design settings unavailable") }
    } } catch (_: Throwable) { promise.reject("E_DESIGN_PREFERENCES", "Local design settings unavailable") }
  }
  @ReactMethod open fun loadPreferences(promise: Promise) = run(promise) {
    if (!dir.exists()) dir.mkdirs()
    val value = if (File(dir, "settings.json").exists()) {
      val bytes = settings.openRead().use { stream ->
        val buffer = ByteArray(2049)
        var count = 0
        while (count < buffer.size) {
          val read = stream.read(buffer, count, buffer.size - count)
          if (read < 0) break
          check(read > 0)
          count += read
        }
        buffer.copyOf(count)
      }
      // Obsolete/truncated JSON is recoverable. I/O errors still reject honestly.
      if (bytes.size > 2048) JSONObject() else try {
        JSONObject(String(bytes, Charsets.UTF_8))
      } catch (_: JSONException) { JSONObject() }
    } else JSONObject()
    val output = validated(value)
    val name = value.optString("wallpaperName", "")
    val file = managed(name)
    output.put("wallpaper", if (file != null && validImage(file)) Uri.fromFile(file).toString() else JSONObject.NULL)
    output.toString()
  }
  @ReactMethod open fun savePreferences(json: String, promise: Promise) = run(promise) {
    check(json.length <= 2048)
    check(dir.exists() || dir.mkdirs())
    val input = JSONObject(json)
    check(input.keys().asSequence().toSet() == setOf("theme", "dim", "blur", "showWallpaper", "reduceMotion", "wallpaper"))
    val output = validated(input)
    var copied: File? = null
    val uriText = if (input.isNull("wallpaper")) null else input.getString("wallpaper")
    val wallpaper = uriText?.let {
      val uri = Uri.parse(it)
      check(uri.scheme == "file" && uri.authority.isNullOrEmpty() && uri.query == null && uri.fragment == null)
      val source = File(checkNotNull(uri.path)).canonicalFile
      val saved = managed(source.name)
      // Android may alias /data/user/0 to /data/data. Keep our stable managed
      // path after validation instead of returning a different URI on every save.
      if (saved != null && source == saved.canonicalFile) { check(source.isFile); saved }
      else {
        check(source.parentFile == reactApplicationContext.cacheDir.canonicalFile)
        check(Regex("veil-design-wallpaper-[A-Za-z0-9_-]{1,96}\\.jpg").matches(source.name))
        check(source.isFile && source.length() in 1L..16_777_216L)
        File(dir, "wallpaper-${UUID.randomUUID()}.jpg").also { file ->
          copied = file
          try {
            source.inputStream().use { from -> file.outputStream().use { to -> from.copyTo(to) } }
            check(file.length() in 1L..16_777_216L)
          } catch (error: Throwable) { file.delete(); throw error }
        }
      }
    }
    try {
      output.put("wallpaperName", wallpaper?.name ?: JSONObject.NULL)
      val stream = settings.startWrite()
      try { stream.write(output.toString().toByteArray(Charsets.UTF_8)); settings.finishWrite(stream) }
      catch (error: Throwable) { settings.failWrite(stream); throw error }
    } catch (error: Throwable) { copied?.delete(); throw error }
    // Delete only this module's previous sanitized images after atomic config save.
    dir.listFiles { _, name -> IMAGE_NAME.matches(name) }
      ?.filter { it.canonicalFile != wallpaper?.canonicalFile }?.forEach { it.delete() }
    wallpaper?.let { Uri.fromFile(it).toString() }
  }
  private fun managed(name: String): File? = if (IMAGE_NAME.matches(name)) File(dir, name) else null
  private fun validImage(file: File): Boolean {
    if (!file.isFile || file.length() !in 1L..16_777_216L) return false
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeFile(file.absolutePath, bounds)
    return bounds.outWidth in 1..8192 && bounds.outHeight in 1..8192
  }
  private fun validated(input: JSONObject): JSONObject {
    val theme = input.optString("theme", "OLED").takeIf { it in THEMES } ?: "OLED"
    val dim = input.optDouble("dim", 20.0).takeIf { it.isFinite() && it in 0.0..90.0 } ?: 20.0
    val blur = input.optDouble("blur", 4.0).takeIf { it.isFinite() && it in 0.0..24.0 } ?: 4.0
    return JSONObject().put("theme", theme).put("dim", dim).put("blur", blur)
      .put("showWallpaper", input.opt("showWallpaper") as? Boolean ?: true)
      .put("reduceMotion", input.opt("reduceMotion") as? Boolean ?: false)
  }
  override fun invalidate() { executor.shutdown(); super.invalidate() }
  companion object {
    private val IMAGE_NAME = Regex("wallpaper-[a-f0-9-]{36}\\.jpg")
    private val THEMES = setOf("Veil", "Midnight", "Ocean", "Forest", "OLED")
  }
}
