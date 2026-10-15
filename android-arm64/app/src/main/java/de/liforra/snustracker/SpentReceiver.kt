package de.liforra.snustracker

import android.app.AlarmManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

/**
 * Tells you once when the pouch stops giving anything back.
 *
 * Scheduled with the alarm manager rather than a coroutine, because the moment worth
 * knowing about usually arrives while the app is closed -- a timer that only runs with
 * the app in the foreground would fire exactly when you least need telling.
 */
class SpentReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val name = intent.getStringExtra(EXTRA_PRODUCT) ?: "Der Pouch"
        notify(context, name)
    }

    private fun notify(context: Context, productName: String) {
        ensureChannel(context)

        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("$productName ist leer")
            .setContentText("Gibt nichts mehr ab — rausnehmen lohnt sich.")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(open)
            .build()

        // Posting without the runtime grant throws on Android 13+. Swallowed on
        // purpose: a refused notification permission is a decision, not an error.
        try {
            NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
        } catch (_: SecurityException) {
        }
    }

    companion object {
        private const val CHANNEL = "pouch_spent"
        private const val NOTIFICATION_ID = 1
        private const val EXTRA_PRODUCT = "product"
        private const val REQUEST = 100

        private fun ensureChannel(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
            val channel = NotificationChannel(
                CHANNEL,
                "Pouch ausgeschöpft",
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = "Meldet sich, wenn ein Pouch nichts mehr abgibt."
            }
            context.getSystemService(NotificationManager::class.java)
                ?.createNotificationChannel(channel)
        }

        private fun pending(context: Context, productName: String): PendingIntent =
            PendingIntent.getBroadcast(
                context,
                REQUEST,
                Intent(context, SpentReceiver::class.java).putExtra(EXTRA_PRODUCT, productName),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )

        /**
         * Book the alarm for `inSeconds` from now, replacing any earlier one.
         *
         * Inexact on purpose: exact alarms need a separate permission on Android 12+,
         * and this is a nudge about a pouch, not a train departure. A few minutes of
         * slack costs nothing and asking for the stricter permission would.
         */
        fun schedule(context: Context, productName: String, inSeconds: Long) {
            if (inSeconds <= 0) return
            ensureChannel(context)
            val alarms = context.getSystemService(AlarmManager::class.java) ?: return
            alarms.set(
                AlarmManager.RTC_WAKEUP,
                System.currentTimeMillis() + inSeconds * 1000,
                pending(context, productName),
            )
        }

        /** Called when the pouch comes out early, or rests: the moment no longer applies. */
        fun cancel(context: Context) {
            context.getSystemService(AlarmManager::class.java)
                ?.cancel(pending(context, ""))
            NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
        }
    }
}
