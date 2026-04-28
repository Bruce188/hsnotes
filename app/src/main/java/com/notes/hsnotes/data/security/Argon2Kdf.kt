package com.notes.hsnotes.data.security

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.lambdapioneer.argon2kt.Argon2Version
import java.nio.CharBuffer
import java.nio.charset.CoderResult
import java.nio.charset.StandardCharsets

/**
 * Argon2id key-derivation wrapper.
 *
 * - Always derives a 32-byte KEK (AES-256 keysize).
 * - Encodes the passphrase to UTF-8 bytes inside [useThenWipe] so the byte form
 *   is wiped immediately after the KDF returns.
 * - Wipes the input [CharArray] before returning, even on exception.
 *
 * Plan-mode § Architecture / § Risk Register.
 */
class Argon2Kdf(
    private val argon2: Argon2Kt = Argon2Kt(),
) {

    /**
     * Derive a 32-byte KEK from [passphrase] + [salt] using Argon2id.
     *
     * @throws IllegalArgumentException if [salt] is shorter than 16 bytes.
     */
    fun derive(
        passphrase: CharArray,
        salt: ByteArray,
        @Suppress("ForbiddenMethodCall")  // Review B10: API default; production callers always pass calibrated.
        params: Argon2Params = Argon2Params.default(),
    ): ByteArray {
        require(salt.size >= 16) { "Salt must be at least 16 bytes; got ${salt.size}" }
        return try {
            charsToUtf8(passphrase).useThenWipe(wipe = { wipe() }) { pwBytes ->
                argon2.hash(
                    mode = Argon2Mode.ARGON2_ID,
                    password = pwBytes,
                    salt = salt,
                    tCostInIterations = params.iterations,
                    mCostInKibibyte = params.memoryKiB,
                    parallelism = params.parallelism,
                    hashLengthInBytes = HASH_LENGTH_BYTES,
                    version = Argon2Version.V13,
                ).rawHashAsByteArray()
            }
        } finally {
            passphrase.wipe()
        }
    }

    private fun charsToUtf8(chars: CharArray): ByteArray {
        // Use the encoder directly so we never allocate an intermediate String.
        val cb = CharBuffer.wrap(chars)
        val encoder = StandardCharsets.UTF_8.newEncoder()
        // Worst case: 4 bytes per char (UTF-8).
        val out = java.nio.ByteBuffer.allocate(chars.size * 4 + 16)
        var result: CoderResult = encoder.encode(cb, out, true)
        if (!result.isUnderflow) result.throwException()
        result = encoder.flush(out)
        if (!result.isUnderflow) result.throwException()
        out.flip()
        val bytes = ByteArray(out.remaining())
        out.get(bytes)
        // Scrub the encoder's backing buffer best-effort.
        if (out.hasArray()) {
            val arr = out.array()
            for (i in arr.indices) arr[i] = 0
        }
        return bytes
    }

    companion object {
        const val HASH_LENGTH_BYTES: Int = 32
    }
}

/**
 * Argon2id parameter triple (memory, iterations, parallelism).
 *
 * Defaults pull from [CryptoConfig]; first-run calibration (Task 10.2) may
 * persist adjusted memory in SecurePrefs.
 */
data class Argon2Params(
    val memoryKiB: Int,
    val iterations: Int,
    val parallelism: Int,
) {
    init {
        require(memoryKiB >= CryptoConfig.ARGON2_MEMORY_FLOOR_KIB) {
            "memoryKiB below floor (${CryptoConfig.ARGON2_MEMORY_FLOOR_KIB}); got $memoryKiB"
        }
        require(iterations >= 1) { "iterations must be >= 1; got $iterations" }
        require(parallelism >= 1) { "parallelism must be >= 1; got $parallelism" }
    }

    companion object {
        fun default(): Argon2Params = Argon2Params(
            memoryKiB = CryptoConfig.ARGON2_MEMORY_KIB,
            iterations = CryptoConfig.ARGON2_ITERATIONS,
            parallelism = CryptoConfig.ARGON2_PARALLELISM,
        )

        /**
         * Plan §10.2 — read the persisted calibrated `m` (or fall back to the
         * default 256 MiB) and build an [Argon2Params] with the security-fixed
         * `t` and `p`. The calibrator only ever tunes memory.
         *
         * Returns the same shape regardless of whether calibration has run:
         * fresh installs see the default until [Argon2Calibrator.ensureCalibrated]
         * persists a tuned value at first launch.
         */
        suspend fun calibratedOrDefault(store: CalibratedParamsStore): Argon2Params {
            val m = store.calibratedArgon2MemoryKiB() ?: CryptoConfig.ARGON2_MEMORY_KIB
            return Argon2Params(
                memoryKiB = m,
                iterations = CryptoConfig.ARGON2_ITERATIONS,
                parallelism = CryptoConfig.ARGON2_PARALLELISM,
            )
        }
    }
}
