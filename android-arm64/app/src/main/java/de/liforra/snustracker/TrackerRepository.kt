package de.liforra.snustracker

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** A freshly minted invite: the three enrolment values, when it lapses, and the QR payload. */
data class Invite(
    val serverUrl: String,
    val serverKey: String,
    val code: String,
    /** Unix seconds. */
    val expiresAt: Long,
    val uri: String,
)

/**
 * Owns the native tracker and the small amount of state that has to survive a restart.
 *
 * The device identity blob lives in [EncryptedSharedPreferences], whose master key sits
 * in the hardware-backed Android Keystore. That is what makes the phone the stronger of
 * the two platforms: the device half of the storage key genuinely cannot be extracted
 * from the hardware, whereas on a Linux box without a TPM it is a file with restrictive
 * permissions and nothing more.
 */
class TrackerRepository(context: Context) {

    private val appContext = context.applicationContext

    private val prefs by lazy {
        val masterKey = MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            appContext,
            "snus-identity",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    val isEnrolled: Boolean
        get() = prefs.contains(KEY_DEVICE_ID)

    suspend fun enroll(
        serverUrl: String,
        serverPub: String,
        code: String,
        displayName: String,
    ): NativeResult<Unit> = withContext(Dispatchers.IO) {
        val identity = when (val result = parseResult(NativeBridge.generateIdentity())) {
            is NativeResult.Err -> return@withContext result
            is NativeResult.Ok -> result.value.getString("identity")
        }

        val request = JSONObject().apply {
            put("server_url", serverUrl.trimEnd('/'))
            put("server_pub", serverPub.trim())
            put("code", code.trim().uppercase())
            put("display_name", displayName.ifBlank { android.os.Build.MODEL })
            put("identity", identity)
        }

        when (val result = parseResult(NativeBridge.enroll(request.toString()))) {
            is NativeResult.Err -> result
            is NativeResult.Ok -> {
                prefs.edit()
                    .putString(KEY_IDENTITY, identity)
                    .putString(KEY_DEVICE_ID, result.value.getString("device_id"))
                    .putString(KEY_SERVER_URL, serverUrl.trimEnd('/'))
                    .putString(KEY_SERVER_PUB, serverPub.trim())
                    .apply()
                NativeResult.Ok(Unit)
            }
        }
    }

    /**
     * Unlock and load. Uses the cached lease share when the server cannot be reached, so
     * the home screen still comes up with no signal.
     */
    suspend fun open(): NativeResult<Snapshot> = withContext(Dispatchers.IO) {
        val request = JSONObject().apply {
            put("data_dir", appContext.filesDir.absolutePath)
            put("server_url", prefs.getString(KEY_SERVER_URL, "") ?: "")
            put("server_pub", prefs.getString(KEY_SERVER_PUB, "") ?: "")
            put("device_id", prefs.getString(KEY_DEVICE_ID, "") ?: "")
            put("identity", prefs.getString(KEY_IDENTITY, "") ?: "")
            prefs.getString(KEY_LEASE, null)?.let { put("cached_lease", it) }
            if (prefs.contains(KEY_LEASE_EXPIRES)) {
                put("cached_lease_expires_at", prefs.getLong(KEY_LEASE_EXPIRES, 0))
            }
        }

        when (val opened = parseResult(NativeBridge.open(request.toString()))) {
            is NativeResult.Err -> opened
            is NativeResult.Ok -> {
                // Cache the fresh share so the next cold start works offline.
                opened.value.optString("lease").takeIf { it.isNotBlank() }?.let { share ->
                    prefs.edit()
                        .putString(KEY_LEASE, share)
                        .putLong(KEY_LEASE_EXPIRES, opened.value.optLong("lease_expires_at"))
                        .apply()
                }
                // The very first device on an account has to mint the data key itself;
                // the call is a no-op once one exists.
                if (opened.value.optBoolean("locked") && opened.value.optBoolean("online")) {
                    parseResult(NativeBridge.bootstrapAccount())
                }
                snapshot()
            }
        }
    }

    suspend fun snapshot(): NativeResult<Snapshot> = call { NativeBridge.snapshot() }

    suspend fun startSession(productId: String): NativeResult<Snapshot> =
        call { NativeBridge.startSession(productId) }

    suspend fun endSession(sessionId: String): NativeResult<Snapshot> =
        call { NativeBridge.endSession(sessionId) }

    suspend fun pauseSession(sessionId: String): NativeResult<Snapshot> =
        call { NativeBridge.pauseSession(sessionId) }

    suspend fun resumeSession(sessionId: String): NativeResult<Snapshot> =
        call { NativeBridge.resumeSession(sessionId) }

    suspend fun discardSession(sessionId: String): NativeResult<Snapshot> =
        call { NativeBridge.discardSession(sessionId) }

    suspend fun setProductDuration(productId: String, minutes: Double): NativeResult<Snapshot> =
        call { NativeBridge.setProductDuration(productId, minutes) }

    /**
     * One-time invite for another device. The server only issues the code; the address and
     * the pinned key are this phone's own, so the QR payload is assembled here -- the same
     * `snus://enroll` shape the laptop's `snus invite` prints and [SetupScreen] scans.
     */
    suspend fun createInvite(): NativeResult<Invite> = withContext(Dispatchers.IO) {
        when (val result = parseResult(NativeBridge.createInvite())) {
            is NativeResult.Err -> result
            is NativeResult.Ok -> {
                val url = prefs.getString(KEY_SERVER_URL, "") ?: ""
                val key = prefs.getString(KEY_SERVER_PUB, "") ?: ""
                val code = result.value.getString("code")
                NativeResult.Ok(
                    Invite(
                        serverUrl = url,
                        serverKey = key,
                        code = code,
                        expiresAt = result.value.optLong("expires_at"),
                        uri = "snus://enroll?url=${android.net.Uri.encode(url)}" +
                            "&key=${android.net.Uri.encode(key)}&code=${android.net.Uri.encode(code)}",
                    )
                )
            }
        }
    }

    /** Hand a data key to devices enrolled after this one. Without it they stay locked. */
    suspend fun approveDevices(): NativeResult<Snapshot> =
        call { NativeBridge.approveDevices() }

    suspend fun retireProduct(productId: String): NativeResult<Snapshot> =
        call { NativeBridge.retireProduct(productId) }

    suspend fun updateSubject(bodyMassKg: Double?, metabolismFactor: Double?): NativeResult<Snapshot> =
        call { NativeBridge.updateSubject(bodyMassKg ?: 0.0, metabolismFactor ?: 0.0) }

    suspend fun samples(fromSecs: Long, toSecs: Long, steps: Int): NativeResult<Curves> =
        withContext(Dispatchers.IO) {
            when (val raw = parseResult(NativeBridge.samples(fromSecs, toSecs, steps))) {
                is NativeResult.Ok -> NativeResult.Ok(Curves.from(raw.value))
                is NativeResult.Err -> raw
            }
        }

    suspend fun addProduct(name: String, nominalMg: Double, accent: String?): NativeResult<Snapshot> =
        call { NativeBridge.addProduct(name, nominalMg, accent ?: "") }

    suspend fun sync(): NativeResult<Snapshot> = withContext(Dispatchers.IO) {
        val result = call { NativeBridge.sync() }
        // A sync rotates the lease share; re-cache it or the next offline start fails.
        parseResult(NativeBridge.leaseShare()).let {
            if (it is NativeResult.Ok) {
                it.value.optString("lease").takeIf { share -> share.isNotBlank() }?.let { share ->
                    prefs.edit().putString(KEY_LEASE, share).apply()
                }
            }
        }
        result
    }

    /** Forget everything. Called when the server reports this device revoked. */
    fun wipe() {
        prefs.edit().clear().apply()
        appContext.filesDir.resolve("records.db").delete()
        NativeBridge.close()
    }

    private suspend fun call(block: () -> String): NativeResult<Snapshot> =
        withContext(Dispatchers.IO) {
            when (val result = parseResult(block())) {
                is NativeResult.Err -> result
                is NativeResult.Ok -> NativeResult.Ok(Snapshot.from(result.value))
            }
        }

    private companion object {
        const val KEY_IDENTITY = "identity"
        const val KEY_DEVICE_ID = "device_id"
        const val KEY_SERVER_URL = "server_url"
        const val KEY_SERVER_PUB = "server_pub"
        const val KEY_LEASE = "lease"
        const val KEY_LEASE_EXPIRES = "lease_expires"
    }
}
