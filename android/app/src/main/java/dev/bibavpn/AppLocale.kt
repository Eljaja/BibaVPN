package dev.bibavpn

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat

object AppLocale {
    private const val PREFS = "bibavpn"
    private const val KEY_APP_LANGUAGE = "app_language_tag"

    /** Пусто = системный язык. Иначе: `ru`, `en`, `fa-IR`. */
    fun getSavedLanguageTag(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_APP_LANGUAGE, "") ?: ""

    fun applyStored(context: Context) {
        applyLanguageTag(getSavedLanguageTag(context))
    }

    fun persist(context: Context, languageTag: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_APP_LANGUAGE, languageTag)
            .apply()
        applyLanguageTag(languageTag)
    }

    private fun applyLanguageTag(languageTag: String) {
        if (languageTag.isEmpty()) {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.getEmptyLocaleList())
        } else {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(languageTag))
        }
    }
}
