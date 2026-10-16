package com.flutteride.codweva

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import java.io.IOException
import java.security.GeneralSecurityException

/**
 * مخزن مستقل لمفاتيح مزودي AI.
 * لا يشارك secure_prefs الخاصة بتسجيل الدخول.
 *
 * المزودون المدعومون:
 *   - OpenAI
 *   - Gemini
 *   - OpenRouter
 *   - Custom (مخصص)
 *
 * ملاحظة أمنية:
 *   - يستخدم EncryptedSharedPreferences (AndroidX Security).
 *   - المفتاح الرئيسي محفوظ في Android Keystore.
 *   - في حال تعذر التشفير، لا نحفظ المفتاح في تخزين عادي.
 */
class AiKeyStore(context: Context) {

    private val prefs: SharedPreferences? = try {
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        EncryptedSharedPreferences.create(
            PREFS_NAME,
            masterKeyAlias,
            context.applicationContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    } catch (_: GeneralSecurityException) {
        null
    } catch (_: IOException) {
        null
    }

    // ============================================================
    // هل التخزين المشفّر متاح؟
    // ============================================================
    val isAvailable: Boolean
        get() = prefs != null

    // ============================================================
    // الحفظ
    // ============================================================
    fun save(providerId: String?, value: String?) {
        val p = prefs ?: return
        val key = keyFor(providerId) ?: return

        if (value.isNullOrBlank()) {
            p.edit().remove(key).apply()
        } else {
            p.edit().putString(key, value.trim()).apply()
        }
    }

    // ============================================================
    // القراءة
    // ============================================================
    fun get(providerId: String?): String? {
        val p = prefs ?: return null
        val key = keyFor(providerId) ?: return null
        return p.getString(key, null)
    }

    // ============================================================
    // الحذف
    // ============================================================
    fun clear(providerId: String?) {
        save(providerId, null)
    }

    /**
     * حذف كل المفاتيح.
     */
    fun clearAll() {
        val p = prefs ?: return
        try {
            p.edit()
                .remove(KEY_OPENAI)
                .remove(KEY_GEMINI)
                .remove(KEY_OPENROUTER)
                .remove(KEY_CUSTOM)
                .apply()
        } catch (_: Exception) {
        }
    }

    /**
     * هل يوجد مفتاح محفوظ لمزود؟
     */
    fun has(providerId: String?): Boolean {
        val value = get(providerId)
        return !value.isNullOrBlank()
    }

    // ============================================================
    // تحويل providerId إلى مفتاح داخلي
    // ============================================================
    private fun keyFor(providerId: String?): String? = when (providerId) {
        AiSettings.OPENAI -> KEY_OPENAI
        AiSettings.GEMINI -> KEY_GEMINI
        AiSettings.OPENROUTER -> KEY_OPENROUTER
        AiSettings.CUSTOM -> KEY_CUSTOM
        else -> null
    }

    // ============================================================
    // ثوابت
    // ============================================================
    companion object {
        private const val PREFS_NAME = "ai_secure_prefs"
        private const val KEY_OPENAI = "openai_api_key"
        private const val KEY_GEMINI = "gemini_api_key"
        private const val KEY_OPENROUTER = "openrouter_api_key"
        private const val KEY_CUSTOM = "custom_api_key"
    }
}