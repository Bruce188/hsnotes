package com.notes.hsnotes.data.security

/**
 * Panic-PIN registration + verification. Plan §7.3.
 *
 * The PIN is a short numeric string the user can enter at the unlock prompt
 * INSTEAD of their real passphrase to trigger a silent crypto-erase while
 * appearing to authenticate normally.
 *
 * Design notes:
 *  - [register] takes the real passphrase as a second argument so it can
 *    enforce "PIN must differ from passphrase" without leaking the passphrase
 *    out of the auth-gate's stack frame. Both [pin] and [realPassphrase] are
 *    consumed (zeroized) — the implementation owns wiping them.
 *  - [matches] re-derives the PIN hash and constant-time compares against the
 *    persisted hash. Caller's [input] is NOT wiped — the auth pipeline forwards
 *    the same buffer to the real passphrase derivation when matches returns
 *    false (see [com.notes.hsnotes.ui.auth.AuthViewModel.unlock]).
 */
interface PanicPinApi {
    /**
     * Persist a hashed copy of [pin] so future calls to [matches] can compare.
     *
     * @throws IllegalArgumentException if [pin] is shorter than 6 characters
     *   or equal to [realPassphrase].
     *
     * Wipes both [pin] and [realPassphrase] on every code path.
     */
    suspend fun register(pin: CharArray, realPassphrase: CharArray)

    /**
     * True iff [input] matches the registered PIN. False if no PIN is
     * registered. Uses a constant-time comparison on hashes — does not early
     * exit on mismatch and runs the full KDF even when no PIN exists is NOT
     * required (returning false on absent record is fine; the panic feature
     * is opt-in and its absence is not an attacker-observable signal).
     */
    suspend fun matches(input: CharArray): Boolean
}
