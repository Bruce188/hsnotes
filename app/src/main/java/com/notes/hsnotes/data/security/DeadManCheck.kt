package com.notes.hsnotes.data.security

import android.content.Context
import com.notes.hsnotes.data.settings.AuthStateStore
import com.notes.hsnotes.data.settings.SettingsStore
import java.time.Clock

/**
 * 14-day dead-man check. Plan §7.2.
 *
 * Reads the last successful unlock from BOTH timestamp sources:
 *  - [AuthStateStore.lastAuthSuccessEpoch] — plaintext DataStore (per Plan §4
 *    routing; pre-unlock readability is mandatory for this check, so the
 *    timestamp cannot live behind the DEK).
 *  - [AttestedClock.read] — HMAC-signed Keystore-attested timestamp file
 *    (resists system-clock rollback because the HMAC key never leaves
 *    StrongBox/TEE).
 *
 * Takes the **max** of the two so a single tampered/cleared source does not
 * prevent the wipe. If both sources agree on a recent unlock, no wipe.
 *
 * Spec note on threshold: the plan prose says `now - max > 14d`, but the
 * test name `window_exactly_14d_triggers_wipe` requires `>=`. We use `>=`
 * (test names are authoritative; "14d" in prose is colloquial inclusive).
 *
 * Tamper case: if [keyManager.isSetupComplete] but BOTH timestamp sources are
 * null, the only path there is post-setup deletion of both. We treat that as
 * a dead-man trigger (cryptoErase) — a benign post-setup state would have at
 * minimum the setup-time write. Plan-mode prose is silent on this case; we
 * fail closed.
 */
class DeadManCheck(
    private val keyManager: KeyManagerApi,
    private val authState: AuthStateStore,
    private val attestedClock: AttestedClock,
    private val clock: Clock = Clock.systemUTC(),
    private val deadManWindowMs: Long = CryptoConfig.DEAD_MAN_WINDOW_MS,
) {

    /**
     * Run the check. No-op if setup is incomplete (first-launch — there is no
     * DEK to erase yet, so the window doesn't apply).
     */
    suspend fun run() {
        if (!keyManager.isSetupComplete()) return

        val authEpoch = authState.lastAuthSuccessEpoch()
        val attestedEpoch = attestedClock.read()
        val maxEpoch = maxOfNullable(authEpoch, attestedEpoch)

        if (maxEpoch == null) {
            // Setup exists but both timestamp sources are gone — tamper signal.
            triggerWipe()
            return
        }

        val elapsed = clock.millis() - maxEpoch
        if (elapsed >= deadManWindowMs) {
            triggerWipe()
        }
    }

    /**
     * Update both timestamp sources to "now". Called from [com.notes.hsnotes.ui.auth.AuthViewModel]
     * after a successful unlock so future runs of [run] see the fresh timestamp.
     */
    suspend fun recordSuccess() {
        val now = clock.millis()
        authState.setLastAuthSuccessEpoch(now)
        attestedClock.write(now)
    }

    private suspend fun triggerWipe() {
        keyManager.cryptoErase()
        authState.setLastAuthSuccessEpoch(null)
        attestedClock.clear()
    }

    private fun maxOfNullable(a: Long?, b: Long?): Long? = when {
        a == null && b == null -> null
        a == null -> b
        b == null -> a
        else -> if (a >= b) a else b
    }

    companion object {
        /**
         * Production entry point — wired into `App.onCreate` as the first
         * line so any wipe fires before the rest of the process initialises
         * and before any UI is composed.
         */
        suspend fun run(context: Context) {
            DeadManCheck(
                keyManager = KeyManager(context),
                authState = SettingsStore(context),
                attestedClock = KeystoreAttestedClock(context),
            ).run()
        }
    }
}
