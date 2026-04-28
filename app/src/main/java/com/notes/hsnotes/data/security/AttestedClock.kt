package com.notes.hsnotes.data.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Last-success timestamp source independent of the system clock. Plan §7.2.
 *
 * Production [KeystoreAttestedClock] persists 8 BE bytes of `epochMs` followed
 * by a 32-byte HMAC-SHA256 tag computed under a Keystore-resident HMAC key
 * (alias [CryptoConfig.KEYSTORE_ALIAS_ATTESTED_CLOCK], distinct from the KEK
 * alias). An attacker rolling the system clock cannot move this stored value
 * forward without the Keystore key — and tampering with the file invalidates
 * the HMAC, in which case [read] returns null. [DeadManCheck] takes the max of
 * this source and the plaintext DataStore source so a tampered or missing
 * attested file falls back to the other side and still triggers the wipe.
 *
 * Tests substitute a pure-memory fake (see `DeadManCheckTest`).
 */
interface AttestedClock {
    /**
     * Last persisted epoch-millis, or null if the file is missing, the HMAC
     * tag does not verify, or the Keystore key is gone. Null is the failure
     * mode — never throw.
     */
    suspend fun read(): Long?

    /** Persist [epochMs] with a fresh HMAC tag. Replaces any prior value atomically. */
    suspend fun write(epochMs: Long)

    /** Remove the timestamp file and the Keystore alias. Idempotent. */
    suspend fun clear()
}

/**
 * Keystore-backed [AttestedClock]. The HMAC key lives at
 * [CryptoConfig.KEYSTORE_ALIAS_ATTESTED_CLOCK] in `AndroidKeyStore`. The
 * payload file is `<filesDir>/sec/attested_ts.bin`.
 *
 * Format: `[8 bytes BE epochMs][32 bytes HMAC-SHA256(epochMs)]`. The HMAC is
 * computed over the 8-byte epoch so the file is self-validating; we don't
 * include any secret in the message.
 */
class KeystoreAttestedClock(
    private val context: Context,
) : AttestedClock {

    private val secDir: File
        get() = File(context.filesDir, CryptoConfig.SEC_DIR_NAME).apply {
            if (!exists()) mkdirs()
        }

    private val tsFile: File get() = File(secDir, ATTESTED_TS_FILENAME)

    override suspend fun read(): Long? = withContext(Dispatchers.IO) {
        if (!tsFile.exists()) return@withContext null
        runCatching {
            val bytes = tsFile.readBytes()
            if (bytes.size != PAYLOAD_BYTES + TAG_BYTES) return@runCatching null
            val key = loadKey() ?: return@runCatching null
            val payload = bytes.copyOfRange(0, PAYLOAD_BYTES)
            val tag = bytes.copyOfRange(PAYLOAD_BYTES, bytes.size)
            val expected = mac(key, payload)
            if (!constantTimeEquals(tag, expected)) return@runCatching null
            ByteBuffer.wrap(payload).long
        }.getOrNull()
    }

    override suspend fun write(epochMs: Long): Unit = withContext(Dispatchers.IO) {
        val key = loadKey() ?: createKey()
        val payload = ByteBuffer.allocate(PAYLOAD_BYTES).putLong(epochMs).array()
        val tag = mac(key, payload)
        writeFileAtomic(tsFile, payload + tag)
    }

    override suspend fun clear(): Unit = withContext(Dispatchers.IO) {
        runCatching { if (tsFile.exists()) tsFile.delete() }
        runCatching {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            if (ks.containsAlias(CryptoConfig.KEYSTORE_ALIAS_ATTESTED_CLOCK)) {
                ks.deleteEntry(CryptoConfig.KEYSTORE_ALIAS_ATTESTED_CLOCK)
            }
        }
    }

    private fun loadKey(): SecretKey? = runCatching {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        ks.getKey(CryptoConfig.KEYSTORE_ALIAS_ATTESTED_CLOCK, null) as? SecretKey
    }.getOrNull()

    private fun createKey(): SecretKey {
        val gen = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            KEYSTORE_PROVIDER,
        )
        gen.init(
            KeyGenParameterSpec.Builder(
                CryptoConfig.KEYSTORE_ALIAS_ATTESTED_CLOCK,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return gen.generateKey()
    }

    private fun mac(key: SecretKey, payload: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(key)
        return m.doFinal(payload)
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }

    private fun writeFileAtomic(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, "${target.name}.new")
        FileOutputStream(tmp).use { fos ->
            fos.write(bytes)
            fos.flush()
            fos.fd.sync()
        }
        try {
            Files.move(
                tmp.toPath(),
                target.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE,
            )
        } catch (_: Throwable) {
            if (target.exists()) target.delete()
            if (!tmp.renameTo(target)) throw IOException("Atomic rename failed for ${target.name}")
        }
    }

    companion object {
        const val ATTESTED_TS_FILENAME: String = "attested_ts.bin"
        private const val PAYLOAD_BYTES: Int = 8
        private const val TAG_BYTES: Int = 32
        private const val KEYSTORE_PROVIDER: String = "AndroidKeyStore"
    }
}
