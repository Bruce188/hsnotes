package com.notes.hsnotes.data.settings

/**
 * Narrow surface the auth gate needs from [SettingsStore]. Lives separately
 * so [com.notes.hsnotes.ui.auth.AuthViewModel] unit tests can inject a
 * pure in-memory fake without dragging DataStore + temp files into the JVM
 * test JVM.
 *
 * The fields here are the **plaintext** auth-state fields from Plan §4 —
 * they must be readable pre-unlock so the wipe ladder, dead-man timer, and
 * panic-PIN compare can run before any DEK is derived. Sensitive UI prefs
 * route through [com.notes.hsnotes.data.security.SecurePrefs] and are
 * not part of this contract.
 */
interface AuthStateStore {
    /** Snapshot of the persisted consecutive-failure counter. */
    suspend fun currentFailCount(): Int

    /** Set the persisted consecutive-failure counter (must be >= 0). */
    suspend fun setFailCount(n: Int)

    /** Record (or clear) the wall-clock millis of the most recent successful unlock. */
    suspend fun setLastAuthSuccessEpoch(epochMs: Long?)

    /**
     * Snapshot of the persisted last-success wall-clock millis, or null if no
     * successful unlock has been recorded (or it was cleared by [setLastAuthSuccessEpoch]
     * with `null`). Used by [com.notes.hsnotes.data.security.DeadManCheck]
     * pre-unlock — therefore must not require an unlocked SecurePrefs binding.
     */
    suspend fun lastAuthSuccessEpoch(): Long?
}
