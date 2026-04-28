package com.notes.hsnotes.data.settings

import android.content.Context
import androidx.annotation.VisibleForTesting
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.notes.hsnotes.data.security.CalibratedParamsStore
import com.notes.hsnotes.data.security.LongKey
import com.notes.hsnotes.data.security.PanicPinRecord
import com.notes.hsnotes.data.security.PanicPinStore
import com.notes.hsnotes.data.security.SecurePrefs
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import java.util.Base64

private val Context.settingsDataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

/**
 * App settings + auth lockout state.
 *
 * Storage routing (Plan §4):
 *  - **Sensitive UI prefs** (lock timeout): SecurePrefs when bound; plaintext
 *    DataStore when unbound. Phase 8 (migration wizard) will move existing
 *    plaintext rows into SecurePrefs on first unlock.
 *  - **Language**: ALWAYS plaintext. [com.notes.hsnotes.App.applyPersistedLanguage]
 *    reads it pre-unlock from `Application.onCreate`; the language tag is not
 *    sensitive.
 *  - **Auth state** (failCount, lastAuthSuccessEpoch, panicPinHash): ALWAYS
 *    plaintext. The wipe ladder + dead-man check + panic-PIN compare must
 *    run pre-unlock, which means they cannot live behind the DEK.
 *
 * Construction is unchanged for callers — `SettingsStore(context)`. Phase 5
 * calls [bindSecurePrefs] after a successful unlock; Phase 6 calls
 * [unbindSecurePrefs] when the lifecycle lock fires.
 */
class SettingsStore @VisibleForTesting internal constructor(
    private val dataStore: DataStore<Preferences>,
) : AuthStateStore, PanicPinStore, CalibratedParamsStore {

    /** Production constructor — used by Application code. */
    constructor(context: Context) : this(context.applicationContext.settingsDataStore)


    data class Settings(
        val language: String? = null,
        val lastAuthSuccessEpoch: Long? = null,
        val failCount: Int = 0,
        val panicPinHash: ByteArray? = null,
        val lockTimeoutMs: Long = 60_000L,
    ) {
        // Auto-generated equals/hashCode use ByteArray identity, which breaks
        // structural comparison in tests. Override for value-equality.
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Settings) return false
            return language == other.language &&
                lastAuthSuccessEpoch == other.lastAuthSuccessEpoch &&
                failCount == other.failCount &&
                (panicPinHash?.contentEquals(other.panicPinHash) ?: (other.panicPinHash == null)) &&
                lockTimeoutMs == other.lockTimeoutMs
        }

        override fun hashCode(): Int {
            var result = language?.hashCode() ?: 0
            result = 31 * result + (lastAuthSuccessEpoch?.hashCode() ?: 0)
            result = 31 * result + failCount
            result = 31 * result + (panicPinHash?.contentHashCode() ?: 0)
            result = 31 * result + lockTimeoutMs.hashCode()
            return result
        }
    }

    private object Keys {
        val LANGUAGE = stringPreferencesKey("language")
        val LOCK_TIMEOUT_MS = longPreferencesKey("lock_timeout_ms")

        // Auth state (always plaintext — pre-unlock readable):
        val LAST_AUTH_SUCCESS_EPOCH = longPreferencesKey("last_auth_success_epoch")
        val FAIL_COUNT = intPreferencesKey("fail_count")
        val PANIC_PIN_HASH_B64 = stringPreferencesKey("panic_pin_hash_b64")
        val PANIC_PIN_SALT_B64 = stringPreferencesKey("panic_pin_salt_b64")

        // Calibrated Argon2 memory (Plan §10.2 — pre-unlock readable so the
        // AuthViewModel factory can construct KeyManager with the device's
        // tuned cost before any unlock attempt). Plain integer kibibytes;
        // not sensitive.
        val ARGON2_CALIBRATED_M_KIB = intPreferencesKey("argon2_calibrated_m_kib")
    }

    /** Mirror of the keys above, but as [com.notes.hsnotes.data.security.PrefKey] for SecurePrefs. */
    private object SecureKeys {
        val LOCK_TIMEOUT_MS = LongKey("lock_timeout_ms")
    }

    private val secureRef = MutableStateFlow<SecurePrefs?>(null)

    /** Phase 5 (AuthGate) installs SecurePrefs after successful unlock. */
    fun bindSecurePrefs(prefs: SecurePrefs) {
        secureRef.value = prefs
    }

    /** Phase 6 (LifecycleLock) drops the binding when the lifecycle locks. */
    fun unbindSecurePrefs() {
        secureRef.value = null
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    val flow: Flow<Settings> = secureRef.flatMapLatest { prefs ->
        if (prefs == null) {
            // Unbound — entire snapshot from plaintext DataStore.
            dataStore.data.map { p -> buildSettingsFromPlaintext(p) }
        } else {
            // Bound — sensitive fields from SecurePrefs, language + auth
            // state still from plaintext (per routing rule).
            combine(dataStore.data, prefs.flow) { plain, secure ->
                Settings(
                    language = plain[Keys.LANGUAGE],
                    lastAuthSuccessEpoch = plain[Keys.LAST_AUTH_SUCCESS_EPOCH],
                    failCount = plain[Keys.FAIL_COUNT] ?: 0,
                    panicPinHash = plain[Keys.PANIC_PIN_HASH_B64]?.let {
                        Base64.getDecoder().decode(it)
                    },
                    lockTimeoutMs = secure.values[SecureKeys.LOCK_TIMEOUT_MS.name]?.let {
                        SecureKeys.LOCK_TIMEOUT_MS.fromBytes(it)
                    } ?: 60_000L,
                )
            }
        }
    }

    private fun buildSettingsFromPlaintext(p: Preferences) = Settings(
        language = p[Keys.LANGUAGE],
        lastAuthSuccessEpoch = p[Keys.LAST_AUTH_SUCCESS_EPOCH],
        failCount = p[Keys.FAIL_COUNT] ?: 0,
        panicPinHash = p[Keys.PANIC_PIN_HASH_B64]?.let { Base64.getDecoder().decode(it) },
        lockTimeoutMs = p[Keys.LOCK_TIMEOUT_MS] ?: 60_000L,
    )

    // -------------------------------------------------------------------------
    // Sensitive UI setters — routed through SecurePrefs when bound.
    // -------------------------------------------------------------------------

    suspend fun setLockTimeoutMs(ms: Long) {
        secureRef.value?.set(SecureKeys.LOCK_TIMEOUT_MS, ms)
            ?: dataStore.edit { it[Keys.LOCK_TIMEOUT_MS] = ms }
    }

    // -------------------------------------------------------------------------
    // Language — always plaintext (read pre-unlock from Application.onCreate).
    // -------------------------------------------------------------------------

    suspend fun setLanguage(tag: String?) {
        dataStore.edit { p ->
            if (tag == null) p.remove(Keys.LANGUAGE) else p[Keys.LANGUAGE] = tag
        }
    }

    // -------------------------------------------------------------------------
    // Auth state — always plaintext (pre-unlock readability for wipe ladder
    // + dead-man check + panic-PIN compare).
    // -------------------------------------------------------------------------

    override suspend fun currentFailCount(): Int =
        dataStore.data.first()[Keys.FAIL_COUNT] ?: 0

    override suspend fun setLastAuthSuccessEpoch(epochMs: Long?) {
        dataStore.edit { p ->
            if (epochMs == null) p.remove(Keys.LAST_AUTH_SUCCESS_EPOCH) else p[Keys.LAST_AUTH_SUCCESS_EPOCH] = epochMs
        }
    }

    override suspend fun lastAuthSuccessEpoch(): Long? =
        dataStore.data.first()[Keys.LAST_AUTH_SUCCESS_EPOCH]

    override suspend fun setFailCount(n: Int) {
        require(n >= 0) { "failCount must be non-negative" }
        dataStore.edit { p -> p[Keys.FAIL_COUNT] = n }
    }

    suspend fun setPanicPinHash(hash: ByteArray?) {
        dataStore.edit { p ->
            if (hash == null) {
                p.remove(Keys.PANIC_PIN_HASH_B64)
            } else {
                p[Keys.PANIC_PIN_HASH_B64] = Base64.getEncoder().encodeToString(hash)
            }
        }
    }

    // -------------------------------------------------------------------------
    // PanicPinStore — Plan §7.3.
    //
    // Hash + salt persisted together in a single edit so a partial write cannot
    // leave the record half-formed. Read-side returns null unless BOTH halves
    // exist — defensive against legacy installs that wrote only the hash via
    // the older [setPanicPinHash] path.
    // -------------------------------------------------------------------------

    override suspend fun readPanicPinRecord(): PanicPinRecord? {
        val p = dataStore.data.first()
        val hashB64 = p[Keys.PANIC_PIN_HASH_B64] ?: return null
        val saltB64 = p[Keys.PANIC_PIN_SALT_B64] ?: return null
        return PanicPinRecord(
            hash = Base64.getDecoder().decode(hashB64),
            salt = Base64.getDecoder().decode(saltB64),
        )
    }

    override suspend fun writePanicPinRecord(record: PanicPinRecord) {
        val hashB64 = Base64.getEncoder().encodeToString(record.hash)
        val saltB64 = Base64.getEncoder().encodeToString(record.salt)
        dataStore.edit { p ->
            p[Keys.PANIC_PIN_HASH_B64] = hashB64
            p[Keys.PANIC_PIN_SALT_B64] = saltB64
        }
    }

    override suspend fun clearPanicPinRecord() {
        dataStore.edit { p ->
            p.remove(Keys.PANIC_PIN_HASH_B64)
            p.remove(Keys.PANIC_PIN_SALT_B64)
        }
    }

    // -------------------------------------------------------------------------
    // CalibratedParamsStore — Plan §10.2.
    //
    // Plaintext routing: the AuthViewModel factory must read this BEFORE any
    // unlock has produced a DEK. The persisted value is a single non-sensitive
    // integer (kibibytes) describing the device's tuned Argon2 cost.
    // -------------------------------------------------------------------------

    override suspend fun calibratedArgon2MemoryKiB(): Int? =
        dataStore.data.first()[Keys.ARGON2_CALIBRATED_M_KIB]

    override suspend fun setCalibratedArgon2MemoryKiB(memKiB: Int) {
        require(memKiB >= com.notes.hsnotes.data.security.CryptoConfig.ARGON2_MEMORY_FLOOR_KIB) {
            "calibrated memKiB below floor; got $memKiB"
        }
        dataStore.edit { p -> p[Keys.ARGON2_CALIBRATED_M_KIB] = memKiB }
    }
}
