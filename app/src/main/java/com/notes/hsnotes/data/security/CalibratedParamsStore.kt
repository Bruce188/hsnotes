package com.notes.hsnotes.data.security

/**
 * Pre-unlock-readable persistence of the calibrated Argon2 memory parameter.
 *
 * Plan §10.2 — plan-prose specified `SecurePrefs.ARGON2_CALIBRATED_M` but the
 * AuthViewModel factory must read this BEFORE any unlock has produced a DEK.
 * The store is therefore implemented against plaintext DataStore (same routing
 * as the auth-state surface — see [com.notes.hsnotes.data.settings.AuthStateStore]).
 *
 * The persisted value is a single non-sensitive integer (kibibytes) describing
 * the device's tuned Argon2 cost. It does not reveal any keying material.
 *
 * Reads return `null` until the calibrator has run at least once. Writes are
 * one-shot — once a value is persisted, the wrapped DEK on disk has been keyed
 * to that cost and re-running calibration would invalidate unlock. The
 * production wiring in [Argon2Calibrator.ensureCalibrated] short-circuits when
 * a value is already present.
 */
interface CalibratedParamsStore {
    suspend fun calibratedArgon2MemoryKiB(): Int?
    suspend fun setCalibratedArgon2MemoryKiB(memKiB: Int)
}
