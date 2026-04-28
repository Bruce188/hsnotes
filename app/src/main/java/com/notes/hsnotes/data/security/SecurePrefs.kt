package com.notes.hsnotes.data.security

import android.content.Context
import android.util.Base64
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.notes.hsnotes.data.db.LockedException
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.TinkJsonProtoKeysetFormat
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.aead.PredefinedAeadParameters
import com.google.crypto.tink.subtle.AesGcmJce
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Encrypted Preferences DataStore.
 *
 * Plan §4 — every value is AEAD-encrypted with associated data = the
 * preference key string, so a swap of value-A's ciphertext into key-B's slot
 * fails open. The Tink keyset itself is wrapped under the [Dek] from
 * [KeyManager] and stored beside it. Disposing or zeroizing the DEK breaks
 * the wrapping Aead — subsequent reads throw [LockedException].
 *
 * On-disk layout:
 *  - `securedata` Preferences DataStore — `<keyName> -> base64(ct)`
 *  - `<filesDir>/sec/securedata_keyset.json` — Tink keyset JSON wrapped under the DEK-derived Aead
 */
class SecurePrefs(
    context: Context,
    dek: Dek,
) {

    private val appCtx = context.applicationContext

    /**
     * AES-256-GCM Aead built from [Dek]. Wraps the Tink keyset on disk.
     *
     * Review B6 — Tink's [AesGcmJce] copies the key bytes internally, so the
     * intermediate [ByteArray] returned by [dek.toByteArray] is the only heap
     * reference we control. Capture it, hand to AesGcmJce, then explicitly
     * zero the local before it falls out of scope. The previous `.copyOf()`
     * was dead — neither array was zeroed and DEK material survived on the
     * heap until GC compaction.
     */
    private val wrappingAead: Aead = run {
        val raw = dek.toByteArray()
        try {
            AesGcmJce(raw)
        } finally {
            raw.fill(0)
        }
    }

    @Volatile
    private var primitive: Aead?

    /** File holding the AEAD-wrapped Tink keyset. */
    private val keysetFile: File =
        File(appCtx.filesDir, "${CryptoConfig.SEC_DIR_NAME}/$KEYSET_FILENAME")

    init {
        AeadConfig.register()
        keysetFile.parentFile?.mkdirs()
        primitive = loadOrCreatePrimitive()
    }

    /** Drops the in-memory primitive. Subsequent reads/writes throw [LockedException]. */
    fun dispose() {
        primitive = null
    }

    private fun aeadOrThrow(): Aead = primitive ?: throw LockedException()

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Decrypt and return the value for [key], or null if absent.
     *
     * Throws [LockedException] if the DEK has been zeroized.
     */
    suspend fun <T : Any> get(key: PrefKey<T>): T? {
        val a = aeadOrThrow()
        val raw = appCtx.secureDataStore.data.first()[stringPreferencesKey(key.name)] ?: return null
        val ct = Base64.decode(raw, Base64.NO_WRAP)
        val pt = a.decrypt(ct, key.name.toByteArray(Charsets.UTF_8))
        return key.fromBytes(pt)
    }

    /**
     * Encrypt and persist [value] for [key].
     *
     * Throws [LockedException] if the DEK has been zeroized.
     */
    suspend fun <T : Any> set(key: PrefKey<T>, value: T) {
        val a = aeadOrThrow()
        val pt = key.toBytes(value)
        val ct = a.encrypt(pt, key.name.toByteArray(Charsets.UTF_8))
        val b64 = Base64.encodeToString(ct, Base64.NO_WRAP)
        appCtx.secureDataStore.edit { it[stringPreferencesKey(key.name)] = b64 }
    }

    /**
     * Remove [key] entirely. Throws [LockedException] if the DEK has been zeroized.
     */
    suspend fun remove(key: PrefKey<*>) {
        aeadOrThrow()  // refuse to mutate a locked store
        appCtx.secureDataStore.edit { it.remove(stringPreferencesKey(key.name)) }
    }

    /**
     * Snapshot stream of decrypted values. Each emission decrypts every
     * present key with the live [primitive]. If the DEK has been zeroized
     * mid-collection, downstream consumers see a [LockedException].
     */
    val flow: Flow<SecureSnapshot> = appCtx.secureDataStore.data.map { prefs ->
        val a = aeadOrThrow()
        val out = HashMap<String, ByteArray>(prefs.asMap().size)
        for ((k, v) in prefs.asMap()) {
            val name = k.name
            val ct = Base64.decode(v as String, Base64.NO_WRAP)
            out[name] = a.decrypt(ct, name.toByteArray(Charsets.UTF_8))
        }
        SecureSnapshot(out)
    }

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------

    private fun loadOrCreatePrimitive(): Aead {
        val handle: KeysetHandle = if (keysetFile.exists()) {
            val json = keysetFile.readText(Charsets.UTF_8)
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(json, wrappingAead, EMPTY_AAD)
        } else {
            val newHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM)
            val json = TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(newHandle, wrappingAead, EMPTY_AAD)
            // Atomic write — buffer-then-rename so a torn write never leaves
            // a half-keyset on disk.
            val tmp = File(keysetFile.parentFile, "${KEYSET_FILENAME}.tmp")
            tmp.outputStream().use { fos ->
                fos.write(json.toByteArray(Charsets.UTF_8))
                fos.fd.sync()
            }
            if (!tmp.renameTo(keysetFile)) {
                tmp.copyTo(keysetFile, overwrite = true)
                tmp.delete()
            }
            newHandle
        }
        return handle.getPrimitive(Aead::class.java)
    }

    companion object {
        const val KEYSET_FILENAME = "securedata_keyset.json"
        const val DATASTORE_NAME = "securedata"
        private val EMPTY_AAD: ByteArray = ByteArray(0)
    }
}

/** Decrypted view of the secure prefs store: key string -> raw plaintext bytes. */
data class SecureSnapshot(val values: Map<String, ByteArray>)

/**
 * Type-safe key for [SecurePrefs]. The [name] is used as both the on-disk
 * Preferences key and as Tink AEAD associated data.
 */
sealed class PrefKey<T : Any>(val name: String) {
    abstract fun toBytes(value: T): ByteArray
    abstract fun fromBytes(bytes: ByteArray): T
}

class StringKey(name: String) : PrefKey<String>(name) {
    override fun toBytes(value: String) = value.toByteArray(Charsets.UTF_8)
    override fun fromBytes(bytes: ByteArray) = String(bytes, Charsets.UTF_8)
}

class LongKey(name: String) : PrefKey<Long>(name) {
    override fun toBytes(value: Long): ByteArray =
        ByteBuffer.allocate(java.lang.Long.BYTES).order(ByteOrder.BIG_ENDIAN).putLong(value).array()
    override fun fromBytes(bytes: ByteArray): Long {
        require(bytes.size == java.lang.Long.BYTES) { "LongKey expects 8 bytes, got ${bytes.size}" }
        return ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).long
    }
}

class IntKey(name: String) : PrefKey<Int>(name) {
    override fun toBytes(value: Int): ByteArray =
        ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.BIG_ENDIAN).putInt(value).array()
    override fun fromBytes(bytes: ByteArray): Int {
        require(bytes.size == Integer.BYTES) { "IntKey expects 4 bytes, got ${bytes.size}" }
        return ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).int
    }
}

class BoolKey(name: String) : PrefKey<Boolean>(name) {
    override fun toBytes(value: Boolean) = byteArrayOf(if (value) 1.toByte() else 0.toByte())
    override fun fromBytes(bytes: ByteArray): Boolean {
        require(bytes.size == 1) { "BoolKey expects 1 byte, got ${bytes.size}" }
        return bytes[0] != 0.toByte()
    }
}

class ByteArrayKey(name: String) : PrefKey<ByteArray>(name) {
    override fun toBytes(value: ByteArray) = value.copyOf()
    override fun fromBytes(bytes: ByteArray) = bytes.copyOf()
}

private val Context.secureDataStore: DataStore<Preferences> by preferencesDataStore(name = SecurePrefs.DATASTORE_NAME)
