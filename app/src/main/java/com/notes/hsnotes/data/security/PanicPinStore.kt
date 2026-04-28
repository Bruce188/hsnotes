package com.notes.hsnotes.data.security

/**
 * Storage surface for the panic-PIN hash + salt. Plan §7.3.
 *
 * Implemented by [com.notes.hsnotes.data.settings.SettingsStore], which
 * routes the record to the **plaintext** DataStore (not SecurePrefs) — the
 * panic-PIN compare must run pre-unlock, before any DEK exists. This is the
 * same routing rule as the wipe-ladder fail-counter and the dead-man epoch
 * (see [com.notes.hsnotes.data.settings.AuthStateStore]).
 *
 * Kept narrow + pure-suspend so [PanicPin] JVM unit tests can supply an
 * in-memory fake without dragging DataStore into the JVM test runtime.
 */
interface PanicPinStore {
    /** Read the persisted record, or null if no PIN has been registered. */
    suspend fun readPanicPinRecord(): PanicPinRecord?

    /** Persist [record], replacing any prior PIN. */
    suspend fun writePanicPinRecord(record: PanicPinRecord)

    /** Drop the persisted record (used by wipe paths). */
    suspend fun clearPanicPinRecord()
}

/**
 * Persisted panic-PIN material: the Argon2id hash and the salt used to derive
 * it. Argon2 parameters are NOT stored alongside the record — both register
 * (`PanicPin.register`) and match (`PanicPin.matches`) read live calibrated
 * params from [com.notes.hsnotes.App.argon2Params] (Review B2). Because
 * the calibrator is one-shot/idempotent (`Argon2Calibrator.ensureCalibrated`
 * short-circuits on every run after the first), the params resolved at
 * register-time are identical to those resolved at every match-time for the
 * lifetime of the install. No re-registration path is required.
 */
data class PanicPinRecord(
    val hash: ByteArray,
    val salt: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PanicPinRecord) return false
        return hash.contentEquals(other.hash) && salt.contentEquals(other.salt)
    }

    override fun hashCode(): Int {
        var result = hash.contentHashCode()
        result = 31 * result + salt.contentHashCode()
        return result
    }
}
