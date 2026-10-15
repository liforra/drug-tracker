package de.liforra.snustracker

import org.json.JSONObject

data class Product(
    val id: String,
    val name: String,
    val nominalMg: Double,
    val accent: String?,
    /** Null means it follows the substance model instead of stating its own figure. */
    val defaultDurationSecs: Double? = null,
)

data class OpenSession(
    val sessionId: String,
    val productName: String,
    /** Epoch seconds. The UI ticks its own clock from this rather than polling native. */
    val startedAt: Long,
    val elapsedSecs: Long,
    /** Out of the mouth and resting: the session runs on, absorption does not. */
    val paused: Boolean = false,
    /** Contact time left before the pouch is spent, or null if it has no profile. */
    val releaseLeftSecs: Long? = null,
)

data class Curves(
    val times: List<Long>,
    val nicotine: List<Double>,
    val cotinine: List<Double>,
) {
    companion object {
        fun from(json: JSONObject): Curves {
            fun longs(key: String) = json.optJSONArray(key)?.let { a ->
                (0 until a.length()).map { a.getLong(it) }
            } ?: emptyList()
            fun doubles(key: String) = json.optJSONArray(key)?.let { a ->
                (0 until a.length()).map { a.getDouble(it) }
            } ?: emptyList()
            return Curves(longs("t"), doubles("nicotine"), doubles("cotinine"))
        }
    }
}

data class Snapshot(
    val locked: Boolean = false,
    val online: Boolean = false,
    val pending: Long = 0,
    val products: List<Product> = emptyList(),
    val openSession: OpenSession? = null,
    val nicotineNgMl: Double = 0.0,
    /** ng/mL per minute. How a pouch feels tracks this far better than the level. */
    val nicotineRatePerMin: Double = 0.0,
    val cotinineNgMl: Double = 0.0,
    val todayCount: Int = 0,
    val todayMg: Double = 0.0,
    /** Relative to your own 90-day peak, not to any clinical scale. */
    val toleranceIndex: Double? = null,
    val bodyMassKg: Double = 75.0,
    val bodyMassIsDefault: Boolean = true,
) {
    companion object {
        fun from(json: JSONObject): Snapshot {
            val products = json.optJSONArray("products")?.let { array ->
                (0 until array.length()).map { index ->
                    val item = array.getJSONObject(index)
                    Product(
                        id = item.getString("id"),
                        name = item.getString("name"),
                        nominalMg = item.getDouble("nominal_mg"),
                        accent = item.optString("accent").takeIf { it.isNotBlank() && it != "null" },
                        defaultDurationSecs = if (item.isNull("default_duration_secs")) null
                            else item.getDouble("default_duration_secs"),
                    )
                }
            } ?: emptyList()

            val open = json.optJSONObject("open_session")?.let {
                OpenSession(
                    sessionId = it.getString("session_id"),
                    productName = it.getString("product_name"),
                    startedAt = it.getLong("started_at"),
                    elapsedSecs = it.getLong("elapsed_secs"),
                    paused = it.optBoolean("paused", false),
                    releaseLeftSecs = if (it.isNull("release_left_secs")) null
                        else it.getLong("release_left_secs"),
                )
            }

            return Snapshot(
                locked = json.optBoolean("locked"),
                online = json.optBoolean("online"),
                pending = json.optLong("pending"),
                products = products,
                openSession = open,
                nicotineNgMl = json.optDouble("nicotine_ng_ml", 0.0),
                nicotineRatePerMin = json.optDouble("nicotine_rate_per_min", 0.0),
                cotinineNgMl = json.optDouble("cotinine_ng_ml", 0.0),
                todayCount = json.optInt("today_count"),
                todayMg = json.optDouble("today_mg", 0.0),
                toleranceIndex = if (json.isNull("tolerance_index")) null
                    else json.optDouble("tolerance_index"),
                bodyMassKg = json.optDouble("body_mass_kg", 75.0),
                bodyMassIsDefault = json.optBoolean("body_mass_is_default", true),
            )
        }
    }
}

/** Result of a native call: either the payload or the message the core gave us. */
sealed interface NativeResult<out T> {
    data class Ok<T>(val value: T) : NativeResult<T>
    data class Err(val message: String) : NativeResult<Nothing>
}

fun parseResult(raw: String): NativeResult<JSONObject> = try {
    val json = JSONObject(raw)
    if (json.optBoolean("ok")) {
        NativeResult.Ok(json.optJSONObject("data") ?: JSONObject())
    } else {
        NativeResult.Err(json.optString("error", "Unbekannter Fehler"))
    }
} catch (e: Exception) {
    NativeResult.Err("Antwort unlesbar: ${e.message}")
}
