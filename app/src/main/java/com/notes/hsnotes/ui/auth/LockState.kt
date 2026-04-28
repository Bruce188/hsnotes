package com.notes.hsnotes.ui.auth

/**
 * UI state machine for the auth gate. Plan §5.1, §8.1.
 *
 * Lifecycle:
 *  - [Setup]         — first-launch (no wrapped_dek on disk yet)
 *  - [Locked]        — passphrase prompt; carries failCount + backoffSeconds
 *  - [Unlocking]     — in-flight Argon2 derivation + wrap unlock
 *  - [PanicSpinner]  — Review V-N1: panic-PIN match path. Visually identical to
 *                      [Unlocking] from the user's POV (a coercer sees a normal
 *                      unlock animation) but does NOT mount the post-unlock
 *                      NavHost — repository / database access would crash
 *                      because no DEK was unwrapped on this path. The wipe is
 *                      scheduled in the background and transitions to [Wiped].
 *  - [Migrating]     — Plan §8.1: post-unlock, pre-install plaintext→ciphertext
 *                      upgrade running. Carries (current,total) row counts for
 *                      the wizard progress bar; non-null [Migrating.error]
 *                      flips the wizard into a recovery banner so the user can
 *                      re-auth.
 *  - [Unlocked]      — DEK is live, database installed; UI proceeds
 *  - [Wiped]         — crypto-erase fired (failure threshold, panic PIN, or
 *                      dead-man); subsequent flow shows the "fresh start" path
 */
sealed interface LockState {
    data object Setup : LockState
    data class Locked(val failCount: Int = 0, val backoffSeconds: Int = 0) : LockState
    data object Unlocking : LockState
    data object PanicSpinner : LockState
    data class Migrating(
        val current: Int = 0,
        val total: Int = 0,
        val error: String? = null,
    ) : LockState
    data object Unlocked : LockState
    data object Wiped : LockState
}
