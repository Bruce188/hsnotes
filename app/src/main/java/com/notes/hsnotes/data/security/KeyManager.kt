package com.notes.hsnotes.data.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * KeyManager — heart of the at-rest security retrofit.
 *
 * Key hierarchy (plan-mode § Architecture):
 * ```
 *   passphrase (CharArray)
 *      |  Argon2id(salt, m=256MB, t=4, p=2)
 *      v
 *   KEK (32B, in-memory only)
 *      |  AES-256-GCM (layer 1)
 *      v
 *   wrapped1(DEK)         <- 12B nonce + 48B ciphertext+tag
 *      |  AES-256-GCM under Android Keystore alias `hsnotes_kek_v1`
 *      v                    (StrongBox if available, TEE fallback)
 *   wrapped2 = on-disk `wrapped_dek.bin`
 * ```
 *
 * Public surface is suspend so heavy IO + crypto can run off the main thread.
 *
 * Hard rules (plan):
 * - Never log passphrases, KEKs, DEKs, or wrapped material.
 * - Treat every unlock failure as a generic [WrongPassphrase] — no oracle.
 * - cryptoErase is idempotent; running twice does not throw.
 */
class KeyManager(
    private val context: Context,
    private val kdf: Argon2Kdf = Argon2Kdf(),
    /**
     * Argon2 parameters used for setup + unlock + changePassphrase. Defaulted
     * to [Argon2Params.default] (production: 256MB / t=4 / p=2). Tests can
     * inject lower-cost parameters; the on-disk format is identical.
     */
    @Suppress("ForbiddenMethodCall")  // Review B10: API default; production callers always pass calibrated.
    private val params: Argon2Params = Argon2Params.default(),
) : KeyManagerApi {

    private val secDir: File
        get() = File(context.filesDir, CryptoConfig.SEC_DIR_NAME).apply {
            if (!exists()) mkdirs()
        }

    private val saltFile: File get() = File(secDir, CryptoConfig.KDF_SALT_FILENAME)
    private val wrappedDekFile: File get() = File(secDir, CryptoConfig.WRAPPED_DEK_FILENAME)

    /** True iff both on-disk artefacts AND the Keystore alias exist. */
    override suspend fun isSetupComplete(): Boolean = withContext(Dispatchers.IO) {
        if (!saltFile.exists() || !wrappedDekFile.exists()) return@withContext false
        runCatching {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            ks.containsAlias(CryptoConfig.KEYSTORE_ALIAS_KEK)
        }.getOrDefault(false)
    }

    /**
     * Generate fresh keys. Overwrites any pre-existing setup.
     *
     * Steps:
     *   1. Random 16B salt + random 32B DEK
     *   2. KEK = Argon2id(passphrase, salt)
     *   3. layer1 = AES-GCM(key=KEK)         encrypts 32B DEK
     *   4. Keystore alias created (StrongBox preferred)
     *   5. layer2 = AES-GCM(key=keystoreKey) encrypts layer1 blob
     *   6. Write salt.bin + wrapped_dek.bin
     *
     * Wipes [passphrase] and intermediate KEK/DEK before returning.
     */
    override suspend fun setupNew(passphrase: CharArray): Unit = withContext(Dispatchers.Default) {
        val salt = ByteArray(SALT_LENGTH).also { secureRandom.nextBytes(it) }
        val dek = ByteArray(DEK_LENGTH).also { secureRandom.nextBytes(it) }
        val kek = kdf.derive(passphrase, salt, params) // wipes `passphrase`
        try {
            val layer1 = aesGcmSeal(kek, dek)
            val keystoreKey = createOrReplaceKeystoreKey()
            val layer2 = aesGcmSeal(keystoreKey, layer1)
            writeFileAtomic(saltFile, salt)
            writeFileAtomic(wrappedDekFile, encodeWrappedDek(layer2))
        } finally {
            kek.wipe()
            dek.wipe()
            // salt is not sensitive once on disk (plan-mode); not wiped.
        }
    }

    /**
     * Recover the DEK using [passphrase]. Wipes [passphrase] in a finally.
     *
     * @return Result.success(Dek) on success, Result.failure(WrongPassphrase)
     *         on ANY failure (AEAD mismatch, missing file, missing alias,
     *         IO error). Single failure type prevents an oracle.
     */
    override suspend fun unlock(passphrase: CharArray): Result<Dek> = withContext(Dispatchers.Default) {
        try {
            val salt = readFileOrNull(saltFile) ?: return@withContext Result.failure(WrongPassphrase())
            val wrapped = readFileOrNull(wrappedDekFile) ?: return@withContext Result.failure(WrongPassphrase())
            val layer2Blob = decodeWrappedDek(wrapped) ?: return@withContext Result.failure(WrongPassphrase())
            val keystoreKey = loadKeystoreKey() ?: return@withContext Result.failure(WrongPassphrase())
            val kek = kdf.derive(passphrase, salt, params) // wipes `passphrase`
            try {
                val layer1 = aesGcmOpen(keystoreKey, layer2Blob)
                val dek = aesGcmOpen(kek, layer1)
                if (dek.size != DEK_LENGTH) {
                    dek.wipe()
                    return@withContext Result.failure(WrongPassphrase())
                }
                Result.success(Dek(dek))
            } finally {
                kek.wipe()
            }
        } catch (_: Throwable) {
            // AEADBadTagException, IOException, KeyStoreException — all collapse here.
            Result.failure(WrongPassphrase())
        } finally {
            // Review V-N4 — kdf.derive already wipes on success/failure but the
            // defensive double-wipe is cheap and idempotent. The previous
            // optimisation guarded against re-wipe by checking for non-space
            // chars; that incorrectly skipped wipe for an all-space passphrase
            // if `kdf.derive` threw before its own wipe. Just always wipe.
            passphrase.wipe()
        }
    }

    /**
     * Re-wrap the existing DEK with a new passphrase. Atomic on the
     * wrapped_dek.bin file: writes to `.new`, fsyncs, atomic-renames.
     */
    override suspend fun changePassphrase(old: CharArray, new: CharArray): Unit = withContext(Dispatchers.Default) {
        val unlocked = unlock(old).getOrElse {
            new.wipe()
            throw WrongPassphrase()
        }
        try {
            val newSalt = ByteArray(SALT_LENGTH).also { secureRandom.nextBytes(it) }
            val newKek = kdf.derive(new, newSalt) // wipes `new`
            try {
                val layer1 = aesGcmSeal(newKek, unlocked.toByteArray())
                val keystoreKey = loadKeystoreKey()
                    ?: throw IOException("Keystore alias missing post-setup")
                val layer2 = aesGcmSeal(keystoreKey, layer1)
                writeFileAtomic(wrappedDekFile, encodeWrappedDek(layer2))
                writeFileAtomic(saltFile, newSalt)
            } finally {
                newKek.wipe()
            }
        } finally {
            unlocked.wipe()
        }
    }

    /**
     * Cryptographic erase. Idempotent.
     *
     * Review B7 — Keystore alias is deleted FIRST, then the on-disk wrapped
     * DEK + salt are overwritten + unlinked. Rationale: the Keystore alias
     * is the most defensible component (HSM-backed when StrongBox is
     * available); destroying it first guarantees that any partial-wipe
     * window (process killed mid-erase by OOM / LMK / panic) leaves the
     * remaining files cryptographically useless, rather than orphaning a
     * Keystore alias whose wrapped DEK has already been unlinked.
     *
     *   1. Delete the Keystore alias.
     *   2. Overwrite wrapped_dek.bin with `SecureRandom` bytes, fsync, unlink.
     *   3. Same for salt.bin.
     *
     * After this returns, no future unlock can recover any DEK regardless of
     * passphrase correctness.
     */
    override suspend fun cryptoErase(): Unit = withContext(Dispatchers.IO) {
        runCatching {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            if (ks.containsAlias(CryptoConfig.KEYSTORE_ALIAS_KEK)) {
                ks.deleteEntry(CryptoConfig.KEYSTORE_ALIAS_KEK)
            }
        }
        runCatching { secureDeleteFile(wrappedDekFile) }
        runCatching { secureDeleteFile(saltFile) }
    }

    // ---------- internals ----------

    private fun aesGcmSeal(key: ByteArray, plaintext: ByteArray): ByteArray =
        aesGcmSeal(SecretKeySpec(key, "AES"), plaintext)

    private fun aesGcmSeal(key: SecretKey, plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(GCM_NONCE_LENGTH).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
        val ct = cipher.doFinal(plaintext)
        return nonce + ct
    }

    private fun aesGcmOpen(key: ByteArray, blob: ByteArray): ByteArray =
        aesGcmOpen(SecretKeySpec(key, "AES"), blob)

    private fun aesGcmOpen(key: SecretKey, blob: ByteArray): ByteArray {
        require(blob.size > GCM_NONCE_LENGTH + GCM_TAG_BITS / 8)
        val nonce = blob.copyOfRange(0, GCM_NONCE_LENGTH)
        val ct = blob.copyOfRange(GCM_NONCE_LENGTH, blob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
        return cipher.doFinal(ct)
    }

    private fun encodeWrappedDek(layer2: ByteArray): ByteArray =
        byteArrayOf(WRAPPED_DEK_VERSION) + layer2

    private fun decodeWrappedDek(bytes: ByteArray): ByteArray? {
        if (bytes.isEmpty() || bytes[0] != WRAPPED_DEK_VERSION) return null
        return bytes.copyOfRange(1, bytes.size)
    }

    private fun createOrReplaceKeystoreKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (ks.containsAlias(CryptoConfig.KEYSTORE_ALIAS_KEK)) {
            ks.deleteEntry(CryptoConfig.KEYSTORE_ALIAS_KEK)
        }
        return tryCreateKeystoreKey(strongBox = true) ?: tryCreateKeystoreKey(strongBox = false)
            ?: error("Failed to provision Keystore key")
    }

    private fun tryCreateKeystoreKey(strongBox: Boolean): SecretKey? {
        val builder = KeyGenParameterSpec.Builder(
            CryptoConfig.KEYSTORE_ALIAS_KEK,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            // Android Keystore AES/GCM keys reject a caller-supplied IV unless
            // randomized-encryption is explicitly opted out. We feed a fresh
            // 12-byte SecureRandom IV per encryption (see [aesGcmSeal]); this
            // is equivalent strength to platform-generated IVs and lets the
            // existing envelope format (12B nonce || ct||tag) work uniformly
            // for both software (KEK) and hardware (keystoreKey) keys without
            // a second code path that reads `cipher.iv` after init.
            .setRandomizedEncryptionRequired(false)
        // Biometric invalidation default differs across API levels; only request
        // setInvalidatedByBiometricEnrollment(false) where it exists (API 24+).
        builder.setInvalidatedByBiometricEnrollment(false)
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        return runCatching {
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            gen.init(builder.build())
            gen.generateKey()
        }.getOrElse { t ->
            // StrongBox unavailable on this device — caller retries with strongBox=false.
            // Any failure raised while strongBox=true is treated as "StrongBox refused":
            // the canonical StrongBoxUnavailableException (API 28+), or the
            // plain ProviderException some OEMs throw instead. Both fall through
            // to a null return so the caller retries non-StrongBox-backed.
            // Avoids referencing the API-28-only class symbol on a minSdk-26 build.
            if (strongBox) null else throw t
        }
    }

    private fun loadKeystoreKey(): SecretKey? = runCatching {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        ks.getKey(CryptoConfig.KEYSTORE_ALIAS_KEK, null) as? SecretKey
    }.getOrNull()

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
            // ATOMIC_MOVE rejected by underlying FS; fall back to rename.
            if (target.exists()) target.delete()
            if (!tmp.renameTo(target)) throw IOException("Atomic rename failed for ${target.name}")
        }
    }

    private fun readFileOrNull(file: File): ByteArray? =
        if (file.exists()) runCatching { file.readBytes() }.getOrNull() else null

    private fun secureDeleteFile(file: File) {
        if (!file.exists()) return
        val len = file.length()
        if (len > 0) {
            // Review P-4 — reuse companion-object [secureRandom] singleton
            // instead of allocating a fresh SecureRandom per call. The singleton
            // is already used for key/salt generation; the wipe path benefits
            // from the same lazily-seeded NativePRNG instance with no extra
            // /dev/urandom seed overhead during a panic-triggered wipe.
            val buf = ByteArray(4096)
            FileOutputStream(file).use { fos ->
                var remaining = len
                while (remaining > 0) {
                    val n = minOf(buf.size.toLong(), remaining).toInt()
                    secureRandom.nextBytes(buf)
                    fos.write(buf, 0, n)
                    remaining -= n
                }
                fos.flush()
                fos.fd.sync()
            }
        }
        file.delete()
    }

    companion object {
        const val SALT_LENGTH: Int = 16
        const val DEK_LENGTH: Int = 32
        const val GCM_NONCE_LENGTH: Int = 12
        const val GCM_TAG_BITS: Int = 128
        const val WRAPPED_DEK_VERSION: Byte = 0x01
        private const val KEYSTORE_PROVIDER: String = "AndroidKeyStore"

        private val secureRandom = SecureRandom()
    }
}

/**
 * Data Encryption Key — opaque 32-byte holder with explicit zeroization.
 *
 * Caller is responsible for calling [wipe] when done. SQLCipher and Tink
 * keep their own copies of the bytes; wiping [Dek] does not affect them.
 */
@JvmInline
value class Dek(private val bytes: ByteArray) {
    fun toByteArray(): ByteArray = bytes
    fun wipe() { bytes.wipe() }
}

/** Generic unlock failure; never differentiated to avoid an oracle. */
class WrongPassphrase : Exception("Unlock failed")
