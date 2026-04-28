package com.notes.hsnotes.data.backup

import com.notes.hsnotes.data.security.Argon2Kdf
import com.notes.hsnotes.data.security.Argon2Params
import com.notes.hsnotes.data.security.CryptoConfig
import com.notes.hsnotes.data.security.wipe
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Plan § Encrypted Backup. Age-style envelope, padded to 4 KiB boundary.
 *
 * Wire format (all big-endian; offsets in bytes):
 * ```
 * +----+-----+----+-----+----------------------+-----+
 * |MAGC| VER |SALT| NONC|     CIPHERTEXT       | TAG |
 * | 4  |  1  | 16 | 12  |        N             | 16  |
 * +----+-----+----+-----+----------------------+-----+
 *      \------------- AAD -----------/
 * ```
 * MAGC = ASCII "HSBK"; VER = 0x01.
 *
 * AEAD plaintext layout (inside ciphertext+tag):
 * ```
 * +-------------+-------------------+--------------+
 * | payloadLen  |   JSON payload    |   padding    |
 * |    4        |   payloadLen      |    rest      |
 * +-------------+-------------------+--------------+
 * ```
 * `payloadLen` is a UInt32 — caller MUST NOT exceed 2 GiB. Padding is random
 * bytes drawn from [SecureRandom]. Total file size is rounded up to the next
 * multiple of [BLOCK_SIZE] so simple file-size inference attacks see only the
 * 4 KiB bucket the payload happens to fall into.
 *
 * Backup KDF runs at lower cost than unlock (64 MiB / 3 / 1) — backups travel
 * off-device where attempt-rate-limit cannot be enforced, but extra cost on a
 * single-shot operation hurts user experience more than it hurts an attacker
 * compared to the unlock path's defense-in-depth (5-attempt wipe + per-fail
 * backoff). Plan-mode § Encrypted Backup.
 */
class EncryptedBackupCodec(
    /**
     * Pluggable KDF. Production callers should pass [productionDerive]; JVM
     * unit tests use a deterministic SHA-256 fake (Argon2 has no JVM impl).
     */
    private val derive: suspend (CharArray, ByteArray) -> ByteArray = productionDerive(),
    private val rng: SecureRandom = SecureRandom(),
) {

    /**
     * Encode a [BackupV1] to ciphertext bytes. [passphrase] is wiped before
     * return. Throws [IllegalArgumentException] for empty passphrase.
     */
    suspend fun encode(backup: BackupV1, passphrase: CharArray): ByteArray {
        require(passphrase.isNotEmpty()) { "Backup passphrase must not be empty" }
        val passCopy = passphrase.copyOf()
        try {
            val json = BackupSerializer.encode(backup).toByteArray(StandardCharsets.UTF_8)
            val salt = ByteArray(SALT_BYTES).also { rng.nextBytes(it) }
            val nonce = ByteArray(NONCE_BYTES).also { rng.nextBytes(it) }

            // Pick total file size so file = next 4096 multiple after fixed
            // overhead + payloadLen prefix + JSON.
            val plaintextLenUnpadded = PAYLOAD_LEN_BYTES + json.size
            val totalUnpadded = HEADER_BYTES + plaintextLenUnpadded + TAG_BYTES
            val totalPadded = ((totalUnpadded + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE
            val plaintextLen = totalPadded - HEADER_BYTES - TAG_BYTES
            val padLen = plaintextLen - plaintextLenUnpadded

            val plaintext = ByteArray(plaintextLen)
            // [payloadLen:UInt32 BE]
            writeUInt32BE(plaintext, 0, json.size)
            // [JSON]
            System.arraycopy(json, 0, plaintext, PAYLOAD_LEN_BYTES, json.size)
            // [random padding]
            if (padLen > 0) {
                val pad = ByteArray(padLen).also { rng.nextBytes(it) }
                System.arraycopy(pad, 0, plaintext, PAYLOAD_LEN_BYTES + json.size, padLen)
            }

            // Review V-N5 — derive contract says it wipes passCopy on
            // success/failure, but a native crash or pre-wipe throw could
            // leak the copy. Wrap defensively: if derive throws, wipe
            // passCopy here before rethrowing.
            val key = try {
                derive(passCopy, salt)
            } catch (t: Throwable) {
                passCopy.wipe()
                throw t
            }
            try {
                require(key.size == KEY_BYTES) { "derive must return $KEY_BYTES bytes; got ${key.size}" }
                val aad = buildAad(salt)
                val ct = aesGcmSeal(key, nonce, plaintext, aad)
                // Wipe the plaintext copy now that it's encrypted.
                plaintext.wipe()
                return buildEnvelope(salt, nonce, ct)
            } finally {
                key.wipe()
            }
        } finally {
            passphrase.wipe()
        }
    }

    /**
     * Decode an encrypted backup blob. Throws [WrongBackupPassphrase] for any
     * authentication failure (wrong passphrase, corrupt header, truncated
     * file). The single failure type prevents an oracle. [passphrase] is
     * wiped before return.
     */
    suspend fun decode(bytes: ByteArray, passphrase: CharArray): BackupV1 {
        require(passphrase.isNotEmpty()) { "Backup passphrase must not be empty" }
        val passCopy = passphrase.copyOf()
        try {
            if (bytes.size < HEADER_BYTES + TAG_BYTES) throw WrongBackupPassphrase()
            // Magic + version: throw the same generic failure on mismatch.
            for (i in 0 until MAGIC.size) {
                if (bytes[i] != MAGIC[i]) throw WrongBackupPassphrase()
            }
            if (bytes[MAGIC.size] != VERSION_BYTE) throw WrongBackupPassphrase()

            val saltOffset = MAGIC.size + 1
            val nonceOffset = saltOffset + SALT_BYTES
            val ctOffset = nonceOffset + NONCE_BYTES

            val salt = bytes.copyOfRange(saltOffset, saltOffset + SALT_BYTES)
            val nonce = bytes.copyOfRange(nonceOffset, nonceOffset + NONCE_BYTES)
            val ct = bytes.copyOfRange(ctOffset, bytes.size)

            // Review V-N5 — same defensive wipe on the decode path.
            val key = try {
                derive(passCopy, salt)
            } catch (t: Throwable) {
                passCopy.wipe()
                throw t
            }
            try {
                if (key.size != KEY_BYTES) throw WrongBackupPassphrase()
                val aad = buildAad(salt)
                val plaintext = try {
                    aesGcmOpen(key, nonce, ct, aad)
                } catch (_: Throwable) {
                    throw WrongBackupPassphrase()
                }
                try {
                    if (plaintext.size < PAYLOAD_LEN_BYTES) throw WrongBackupPassphrase()
                    val payloadLen = readUInt32BE(plaintext, 0)
                    if (payloadLen < 0 || payloadLen > plaintext.size - PAYLOAD_LEN_BYTES) {
                        throw WrongBackupPassphrase()
                    }
                    val json = String(
                        plaintext,
                        PAYLOAD_LEN_BYTES,
                        payloadLen,
                        StandardCharsets.UTF_8,
                    )
                    return try {
                        BackupSerializer.decode(json)
                    } catch (t: Throwable) {
                        // Backup blob authenticated but JSON malformed — surface
                        // a distinct path so callers can show a meaningful error.
                        throw CorruptBackupPayload(t)
                    }
                } finally {
                    plaintext.wipe()
                }
            } finally {
                key.wipe()
            }
        } finally {
            passphrase.wipe()
        }
    }

    private fun buildAad(salt: ByteArray): ByteArray {
        val aad = ByteArray(MAGIC.size + 1 + SALT_BYTES)
        System.arraycopy(MAGIC, 0, aad, 0, MAGIC.size)
        aad[MAGIC.size] = VERSION_BYTE
        System.arraycopy(salt, 0, aad, MAGIC.size + 1, SALT_BYTES)
        return aad
    }

    private fun buildEnvelope(salt: ByteArray, nonce: ByteArray, ct: ByteArray): ByteArray {
        val out = ByteArray(HEADER_BYTES + ct.size)
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.size)
        out[MAGIC.size] = VERSION_BYTE
        System.arraycopy(salt, 0, out, MAGIC.size + 1, SALT_BYTES)
        System.arraycopy(nonce, 0, out, MAGIC.size + 1 + SALT_BYTES, NONCE_BYTES)
        System.arraycopy(ct, 0, out, HEADER_BYTES, ct.size)
        return out
    }

    private fun aesGcmSeal(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, nonce),
        )
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun aesGcmOpen(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, nonce),
        )
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    private fun writeUInt32BE(out: ByteArray, offset: Int, value: Int) {
        out[offset] = ((value ushr 24) and 0xFF).toByte()
        out[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        out[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        out[offset + 3] = (value and 0xFF).toByte()
    }

    private fun readUInt32BE(bytes: ByteArray, offset: Int): Int {
        val b0 = bytes[offset].toInt() and 0xFF
        val b1 = bytes[offset + 1].toInt() and 0xFF
        val b2 = bytes[offset + 2].toInt() and 0xFF
        val b3 = bytes[offset + 3].toInt() and 0xFF
        return (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
    }

    companion object {
        val MAGIC: ByteArray = "HSBK".toByteArray(StandardCharsets.US_ASCII)
        const val VERSION_BYTE: Byte = 0x01
        const val SALT_BYTES: Int = 16
        const val NONCE_BYTES: Int = 12
        const val TAG_BYTES: Int = 16
        const val KEY_BYTES: Int = 32
        const val GCM_TAG_BITS: Int = 128
        const val PAYLOAD_LEN_BYTES: Int = 4
        const val BLOCK_SIZE: Int = 4096
        /** Magic(4) + version(1) + salt(16) + nonce(12). */
        const val HEADER_BYTES: Int = 4 + 1 + SALT_BYTES + NONCE_BYTES

        /** Backup KDF cost — lower than unlock (64 MiB / 3 / 1). */
        const val BACKUP_MEMORY_KIB: Int = CryptoConfig.ARGON2_MEMORY_FLOOR_KIB
        const val BACKUP_ITERATIONS: Int = 3
        const val BACKUP_PARALLELISM: Int = 1

        /**
         * Production derive function — Argon2id at backup-cost params.
         * The KDF wipes the input passphrase as part of its contract.
         */
        fun productionDerive(kdf: Argon2Kdf = Argon2Kdf()): suspend (CharArray, ByteArray) -> ByteArray =
            { pass, salt ->
                kdf.derive(
                    passphrase = pass,
                    salt = salt,
                    params = Argon2Params(
                        memoryKiB = BACKUP_MEMORY_KIB,
                        iterations = BACKUP_ITERATIONS,
                        parallelism = BACKUP_PARALLELISM,
                    ),
                )
            }
    }
}

/**
 * Generic authentication failure for encrypted backups. Single failure type
 * prevents oracle attacks (wrong passphrase, corrupt header, truncated file
 * all collapse here).
 */
class WrongBackupPassphrase : Exception("Backup passphrase rejected")

/**
 * Backup decrypted successfully but the JSON payload could not be parsed
 * as a valid [BackupV1]. Signals tampered or version-mismatched backup —
 * distinct from authentication failure to enable a meaningful error message.
 */
class CorruptBackupPayload(cause: Throwable) : Exception("Backup payload malformed", cause)
