package dev.bibavpn.core

/**
 * JNI to Rust `bibavpn-jni`: same stack as desktop `bibavpn-client`.
 * @return null on success, or a human-readable error message.
 */
object BibaNative {
    init {
        System.loadLibrary("bibavpn_jni")
    }

    @JvmStatic
    external fun nativeStart(configJson: String): String?

    @JvmStatic
    external fun nativeStop(): String?

    /** JSON: `{ "ok": true, "server", "token", … }` or `{ "ok": false, "error": "…" }`. */
    @JvmStatic
    external fun nativeDecodeInvite(uri: String, passphrase: String): String
}
