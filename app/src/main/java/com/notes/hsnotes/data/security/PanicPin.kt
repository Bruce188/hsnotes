package com.notes.hsnotes.data.security

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Real panic-PIN implementation. Plan §7.3.
 *
 * Storage:
 *  - hash + salt persisted via [PanicPinStore] (plaintext DataStore — pre-unlock
 *    readable, same routing as fail-counter and dead-man epoch).
 *
 * KDF:
 *  - [derive] is injected so JVM unit tests can use a deterministic SHA-256
 *    fake. Production wires [Argon2Kdf.derive] with the SAME calibrated
 *    [Argon2Params] used by the unlock KDF, so timing differs only by how
 *    the user enters the secret (passphrase vs PIN), not by the work factor.
 *
 * Constant-time:
 *  - [matches] compares hashes via [MessageDigest.isEqual] (constant-time over
 *    equal-length byte arrays — sufficient since hashes are always
 *    [Argon2Kdf.HASH_LENGTH_BYTES] long). Raw PINs never enter the comparison.
 *
 * Buffer hygiene:
 *  - [register] wipes both [pin] and [realPassphrase] on every code path.
 *  - [matches] does NOT wipe [input] — the auth pipeline reuses the same
 *    buffer for the real Argon2id derivation when matches returns false. The
 *    auth pipeline owns wiping it after both passes complete (see
 *    [com.notes.hsnotes.ui.auth.AuthViewModel.unlock]).
 *
 * @param store Plaintext-backed record store.
 * @param derive PIN-hashing function. Production: Argon2id at default cost.
 *   Tests: SHA-256 (deterministic, no JNI).
 * @param onMatch Fired AFTER [matches] confirms a hit (before returning).
 *   Production wires this to defensive cleanup; the auth pipeline still
 *   triggers its own crypto-erase via [WipeManagerApi]. Tests use it to
 *   verify the matches-true path took the callback branch.
 */
class PanicPin(
    private val store: PanicPinStore,
    private val derive: suspend (CharArray, ByteArray) -> ByteArray,
    private val onMatch: suspend () -> Unit = {},
    private val random: SecureRandom = SecureRandom(),
) : PanicPinApi {

    override suspend fun register(pin: CharArray, realPassphrase: CharArray) {
        try {
            require(pin.size >= MIN_PIN_LENGTH) {
                "panic PIN must be >= $MIN_PIN_LENGTH characters; got ${pin.size}"
            }
            require(!pin.contentEquals(realPassphrase)) {
                "panic PIN must differ from the unlock passphrase"
            }
            val salt = ByteArray(SALT_BYTES).also(random::nextBytes)
            // derive() may wipe its CharArray input (Argon2Kdf.derive does).
            // Pass a copy so the finally block can still wipe `pin` deterministically.
            val pinCopy = pin.copyOf()
            val hash = derive(pinCopy, salt)
            store.writePanicPinRecord(PanicPinRecord(hash = hash, salt = salt))
        } finally {
            pin.wipe()
            realPassphrase.wipe()
        }
    }

    override suspend fun matches(input: CharArray): Boolean {
        val record = store.readPanicPinRecord() ?: return false
        // Pass a copy — derive() may wipe its argument.
        val inputCopy = input.copyOf()
        val derived = derive(inputCopy, record.salt)
        try {
            // MessageDigest.isEqual is constant-time over equal-length arrays.
            // Both `derived` and `record.hash` are [Argon2Kdf.HASH_LENGTH_BYTES]
            // long when the production KDF is wired; tests use 32-byte SHA-256.
            val ok = MessageDigest.isEqual(derived, record.hash)
            if (ok) onMatch()
            return ok
        } finally {
            derived.wipe()
        }
    }

    companion object {
        /** Plan §7.3 + Risk Register: PIN must be at least 6 characters. */
        const val MIN_PIN_LENGTH: Int = 6

        /** Argon2id salt size — same as [KeyManager]'s wrap salts. */
        const val SALT_BYTES: Int = 16

        /**
         * Production KDF binding: Argon2id at the caller's calibrated cost.
         * Matches the unlock KDF so panic-PIN matching is indistinguishable
         * from real-passphrase matching from a timing standpoint AND so the
         * panic-PIN derive cannot OOM on a device that calibrated below the
         * 256 MiB default. Review B2 — [params] MUST come from the same
         * source as KeyManager's params (App.argon2Params) so register-time
         * and match-time hashes agree on calibrated devices.
         */
        fun productionDerive(
            params: Argon2Params,
            argon2: Argon2Kdf = Argon2Kdf(),
        ): suspend (CharArray, ByteArray) -> ByteArray =
            { input, salt -> argon2.derive(input, salt, params) }
    }
}
