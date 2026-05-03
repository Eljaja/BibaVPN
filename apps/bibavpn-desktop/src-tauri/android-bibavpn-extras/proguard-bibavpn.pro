# BibaVPN: R8 in release (isMinifyEnabled) strips Tauri / Wry / WebView / JNI glue.
# Symptom: FATAL: NoClassDefFoundError "Class not found using the boot class loader" ~2–4s after start.
# build.gradle.kts already applies fileTree("**/*.pro") under app/ — this file is copied as app/proguard-bibavpn.pro.

-keep class app.tauri.** { *; }
-keep class dev.bibavpn.** { *; }
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}
-dontwarn org.chromium.**
-dontwarn org.conscrypt.**
