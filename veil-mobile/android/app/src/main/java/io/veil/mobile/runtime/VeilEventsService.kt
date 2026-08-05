package io.veil.mobile.runtime

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import uniffi.veil_ffi.MobileWsEventsCallback
import uniffi.veil_ffi.MobileWsEventsController
import uniffi.veil_ffi.MobileWsEventsExit


class VeilEventsService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null
    private var eventsController: MobileWsEventsController? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = createNotification()
        
        // Start foreground service with Data Sync type if API 34+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID, 
                notification, 
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        acquireWakeLock()
        
        val runtime = (applicationContext as io.veil.mobile.MainApplication).veilMobileRuntime

        if (intent?.action == "io.veil.mobile.ACTION_FORCE_RECONNECT") {
            try {
                runtime.mobileReconnectTarget()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to call mobileReconnectTarget", e)
            }
        }

        // Only start the loop if it's not already running
        if (eventsController == null) {
            try {
                val callback = object : MobileWsEventsCallback {
                    override fun onAuthenticated() {
                        Log.i(TAG, "Background WebSocket authenticated")
                    }

                    override fun onEventsReady() {
                        Log.i(TAG, "Background events ready, notifying sync engine")
                        runtime.onBackgroundEventsReady()
                    }

                    override fun onTerminal(exit: MobileWsEventsExit) {
                        Log.w(TAG, "Background WebSocket terminal: $exit")
                        stopSelf()
                    }
                }
                val controller = runtime.startBackgroundEvents(Build.MODEL, "Android", callback)
                if (controller == null) {
                    Log.i(TAG, "Background events not started: native session is locked")
                    stopSelf()
                    return START_NOT_STICKY
                }
                eventsController = controller
                Log.i(TAG, "Rust supervisor loop started (runWsEventsV3)")
            } catch (e: Exception) {
                Log.e(TAG, "Rust supervisor loop failed", e)
                stopSelf()
            }
        }

        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        eventsController?.stop()
        eventsController = null
        releaseWakeLock()
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null // We don't provide binding for this service
    }

    private fun acquireWakeLock() {
        if (wakeLock == null) {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "Veil::WsEventsWakeLock"
            ).apply {
                acquire(WAKELOCK_TIMEOUT_MS)
                Log.i(TAG, "WakeLock acquired")
            }
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
                Log.i(TAG, "WakeLock released")
            }
        }
        wakeLock = null
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Background Events",
                NotificationManager.IMPORTANCE_LOW // No sound or visual intrusion
            ).apply {
                description = "Keeps the secure WebSocket connected in the background"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Connecting...") // TODO: Replace with localized strings
            .setContentText("Syncing secure events")
            // Make sure ic_veil_launcher or a specific service icon exists
            .setSmallIcon(android.R.drawable.ic_popup_sync) 
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "VeilEventsService"
        private const val CHANNEL_ID = "veil_events_channel"
        private const val NOTIFICATION_ID = 4001
        
        // WakeLock timeout to prevent battery drain in case of infinite hangs
        private const val WAKELOCK_TIMEOUT_MS = 10 * 60 * 1000L // 10 minutes
    }
}
