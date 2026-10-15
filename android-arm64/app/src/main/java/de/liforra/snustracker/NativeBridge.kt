package de.liforra.snustracker

/**
 * The Rust core, as seen from Kotlin.
 *
 * Everything crosses as JSON. The alternative -- generated bindings -- buys nicer types
 * at the cost of a code generator in the build; with a surface this small the JSON is
 * the cheaper trade, and it keeps the Rust side free of JNI types.
 *
 * Every call returns `{"ok":true,"data":...}` or `{"ok":false,"error":"..."}`.
 * All of them block, so none may run on the main thread.
 */
object NativeBridge {
    init {
        System.loadLibrary("tracker_jni")
        initLogging()
    }

    external fun initLogging()
    external fun generateIdentity(): String
    external fun enroll(requestJson: String): String
    external fun open(requestJson: String): String
    external fun snapshot(): String
    external fun startSession(productId: String): String
    external fun endSession(sessionId: String): String
    external fun pauseSession(sessionId: String): String
    external fun resumeSession(sessionId: String): String
    external fun discardSession(sessionId: String): String
    external fun setProductDuration(productId: String, minutes: Double): String
    external fun retireProduct(productId: String): String
    /** Pass 0.0 for a value that should stay as it is: JNI primitives have no null. */
    external fun updateSubject(bodyMassKg: Double, metabolismFactor: Double): String
    external fun samples(fromSecs: Long, toSecs: Long, steps: Int): String
    external fun addProduct(name: String, nominalMg: Double, accent: String): String
    external fun sync(): String
    external fun leaseShare(): String
    external fun approveDevices(): String
    external fun createInvite(): String
    external fun bootstrapAccount(): String
    external fun close(): String
}
