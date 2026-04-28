package com.notes.hsnotes.ui.auth

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.notes.hsnotes.App
import com.notes.hsnotes.data.security.Argon2Params
import com.notes.hsnotes.data.security.AttestedClock
import com.notes.hsnotes.data.security.CryptoConfig
import com.notes.hsnotes.data.security.Dek
import com.notes.hsnotes.data.security.KeyManager
import com.notes.hsnotes.data.security.KeyManagerApi
import com.notes.hsnotes.data.security.KeystoreAttestedClock
import com.notes.hsnotes.data.security.PanicPin
import com.notes.hsnotes.data.security.PanicPinApi
import com.notes.hsnotes.data.security.WipeLevel
import com.notes.hsnotes.data.security.WipeManager
import com.notes.hsnotes.data.security.WipeManagerApi
import com.notes.hsnotes.data.security.wipe
import com.notes.hsnotes.data.migration.PlaintextToCipherMigration
import com.notes.hsnotes.data.settings.AuthStateStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.time.Clock

/**
 * Auth gate state machine. Plan §5.1.
 *
 * Lifecycle:
 *  - First emission is always [LockState.Locked] (the "boot" placeholder); the
 *    init coroutine then resolves to [LockState.Setup] (no wrapped DEK on
 *    disk) or [LockState.Locked] (wrapped DEK present, prompt for passphrase).
 *  - [unlock] runs the panic-PIN compare BEFORE the real Argon2id derivation —
 *    on match it emits [LockState.Unlocked] for [PANIC_FAKE_UNLOCK_MS]ms (so a
 *    coercer sees a normal unlock animation) then drops the DEK + emits
 *    [LockState.Wiped]. The fake-unlock is non-blocking — the launching
 *    coroutine returns immediately so the UI thread is never stalled.
 *  - On real unlock success, [onUnlocked] runs INSIDE the same coroutine so
 *    callers can install the database / bind SecurePrefs before the UI
 *    transitions to [LockState.Unlocked]. This is important for FLAG_SECURE
 *    correctness — Phase 6 needs the bind to land before any composable that
 *    reads `repository` runs.
 *  - On failure, [CryptoConfig.WIPE_FAIL_THRESHOLD] consecutive misses fire a
 *    crypto-erase. Sub-threshold misses surface a backoff from
 *    [CryptoConfig.LOCKOUT_SCHEDULE_SECONDS].
 *
 * Dependency note: the plan originally specified `securePrefs: SecurePrefs?`
 * here, but Phase 4 moved auth state (failCount + lastAuthSuccessEpoch +
 * panicPinHash) out of SecurePrefs into plaintext DataStore — those fields
 * MUST be readable pre-unlock. So the auth gate depends on [AuthStateStore]
 * (the narrow plaintext-auth surface implemented by SettingsStore) instead.
 */
class AuthViewModel(
    private val keyManager: KeyManagerApi,
    private val wipeManager: WipeManagerApi,
    private val panicPin: PanicPinApi,
    private val authState: AuthStateStore,
    private val clock: Clock = Clock.systemUTC(),
    private val onUnlocked: suspend (Dek) -> Unit = {},
    /**
     * Plan §6.1 — fired by [com.notes.hsnotes.data.security.LifecycleLock]
     * when the idle timeout elapses. The collector flips state back to
     * [LockState.Locked] via [enterBackground]. Optional so JVM unit tests
     * can inject `null` and avoid wiring a fake flow when not exercising the
     * lifecycle path.
     */
    lockSignal: SharedFlow<Unit>? = null,
    /**
     * Plan §7.2 — Keystore-attested timestamp source for the dead-man check.
     * On every successful unlock we write `clock.millis()` to BOTH the
     * plaintext [AuthStateStore] (already covered) AND this attested source,
     * so [com.notes.hsnotes.data.security.DeadManCheck] can take the max
     * of the two on next `App.onCreate`. Optional so JVM unit tests that do
     * not exercise the dead-man path can pass `null`.
     */
    private val attestedClock: AttestedClock? = null,
    /**
     * Plan §8.1 — plaintext-to-ciphertext upgrade. When present and a
     * plaintext database is detected, the unlock pipeline runs the migration
     * BEFORE invoking [onUnlocked] (which opens the ciphertext DB). Optional
     * so JVM unit tests that do not exercise the migration path can pass
     * `null`.
     */
    private val migration: PlaintextToCipherMigration? = null,
) : ViewModel() {

    private val _state = MutableStateFlow<LockState>(LockState.Locked())
    val state: StateFlow<LockState> = _state.asStateFlow()

    /** Mirrors the persisted failCount so [enterBackground] can rebuild Locked without re-reading DataStore. */
    private var currentFailCount: Int = 0

    /**
     * Review v3-N2 — re-entry guard for [unlock].
     *
     * The panic path holds [LockState.PanicSpinner] for [PANIC_FAKE_UNLOCK_MS]
     * before crypto-erase fires. Without a guard, a second [unlock] call fired
     * during that window (deep link, IPC, automation, instrumentation) would
     * launch a real `keyManager.unlock` concurrently with the pending wipe; if
     * the second passphrase is correct, [LockState.Unlocked] could land before
     * the wipe completes and surface the post-unlock NavHost over a process
     * whose Keystore alias is about to be deleted.
     *
     * Reads/writes happen on the Main dispatcher (viewModelScope.launch with
     * `Dispatchers.Main.immediate`); plain @Volatile suffices, no atomic.
     */
    @Volatile
    private var unlockInFlight: Boolean = false

    init {
        viewModelScope.launch {
            currentFailCount = authState.currentFailCount()
            _state.value = if (keyManager.isSetupComplete()) {
                LockState.Locked(failCount = currentFailCount)
            } else {
                LockState.Setup
            }
        }
        if (lockSignal != null) {
            viewModelScope.launch {
                lockSignal.collect {
                    enterBackground()
                }
            }
        }
    }

    /**
     * Run the unlock pipeline. Caller's [passphrase] is consumed — never reuse it.
     *
     * - Panic match → emits [LockState.Unlocked], schedules a delayed crypto-erase, then [LockState.Wiped].
     * - Real success → resets failCount, persists `lastAuthSuccessEpoch`, runs [onUnlocked], emits [LockState.Unlocked].
     * - Real failure → increments failCount; threshold reached → wipe + [LockState.Wiped]; else [LockState.Locked] with backoff.
     */
    fun unlock(passphrase: CharArray) {
        viewModelScope.launch {
            // Review v3-N2 — bail before any side effects if a prior unlock is
            // still in flight (panic spinner window OR real unlock pending).
            // Caller's passphrase must still be wiped on the early-return path.
            if (unlockInFlight) {
                passphrase.wipe()
                return@launch
            }
            unlockInFlight = true
            try {
                unlockBody(passphrase)
            } finally {
                unlockInFlight = false
            }
        }
    }

    private suspend fun unlockBody(passphrase: CharArray) {
            // 1. Panic-PIN compare runs first so it cannot leak via Argon2 timing.
            // Review B5 — passphrase MUST be wiped even if matches() throws
            // (DataStore IO error, Argon2 native crash, store corruption).
            // The passphrase still flows into keyManager.unlock on the
            // matches=false path; KeyManager wipes there. Only the
            // matches-throws and matches-true paths need explicit wipes here.
            val panicHit = try {
                panicPin.matches(passphrase)
            } catch (t: Throwable) {
                passphrase.wipe()
                throw t
            }
            if (panicHit) {
                passphrase.wipe()
                // Review V-N1 — must NOT route to LockState.Unlocked here:
                // MainActivity mounts the post-unlock NavHost on Unlocked,
                // HomeViewModel.init reads `app.repository`, which throws
                // LockedException because installDatabase never ran on this
                // path. PanicSpinner renders the same indeterminate progress
                // UI as Unlocking so the coercer still sees a normal animation
                // for [PANIC_FAKE_UNLOCK_MS] before the crypto-erase fires.
                _state.value = LockState.PanicSpinner
                delay(PANIC_FAKE_UNLOCK_MS)
                wipeManager.wipeNow(WipeLevel.CRYPTO_ERASE)
                _state.value = LockState.Wiped
                return
            }

            // 2. Real unlock. KeyManager.unlock wipes passphrase.
            _state.value = LockState.Unlocking
            val result = keyManager.unlock(passphrase)
            result.fold(
                onSuccess = { dek ->
                    currentFailCount = 0
                    authState.setFailCount(0)
                    val now = clock.millis()
                    authState.setLastAuthSuccessEpoch(now)
                    attestedClock?.write(now)

                    // Plan §8.1 — migrate any pre-retrofit plaintext database
                    // BEFORE installDatabase opens the encrypted file. Failure
                    // here drops the DEK, leaves plaintext intact, and surfaces
                    // an error banner the user can dismiss back to Locked.
                    val mig = migration
                    if (mig != null && mig.isPlaintextPresent()) {
                        _state.value = LockState.Migrating(0, 0)
                        val migResult = mig.migrate(dek.toByteArray()) { cur, tot ->
                            _state.value = LockState.Migrating(cur, tot)
                        }
                        if (migResult.isFailure) {
                            dek.wipe()
                            _state.value = LockState.Migrating(
                                current = 0,
                                total = 0,
                                error = migResult.exceptionOrNull()?.message ?: "migration failed",
                            )
                            return@fold
                        }
                    }

                    onUnlocked(dek)
                    _state.value = LockState.Unlocked
                },
                onFailure = {
                    currentFailCount += 1
                    authState.setFailCount(currentFailCount)
                    if (currentFailCount >= CryptoConfig.WIPE_FAIL_THRESHOLD) {
                        wipeManager.wipeNow(WipeLevel.CRYPTO_ERASE)
                        _state.value = LockState.Wiped
                    } else {
                        val schedule = CryptoConfig.LOCKOUT_SCHEDULE_SECONDS
                        val idx = (currentFailCount - 1).coerceIn(0, schedule.size - 1)
                        _state.value = LockState.Locked(
                            failCount = currentFailCount,
                            backoffSeconds = schedule[idx],
                        )
                    }
                },
            )
    }

    /**
     * First-launch path. Provisions fresh KEK + DEK material under [passphrase],
     * optionally registers a panic PIN, then immediately performs an unlock so
     * downstream consumers ([onUnlocked]) receive the DEK on the same flow.
     *
     * Caller's [passphrase] and [panicPinChars] are consumed — never reuse them.
     */
    fun setupNew(passphrase: CharArray, panicPinChars: CharArray?) {
        viewModelScope.launch {
            _state.value = LockState.Unlocking
            // KeyManager.setupNew wipes passphrase. We need:
            //  - unlockCopy: re-derive Argon2 immediately to land DEK + onUnlocked.
            //  - regCopy: pass the passphrase into PanicPin.register so it can
            //    enforce "PIN must differ from passphrase" without the auth gate
            //    leaking the passphrase outside this stack frame.
            // Both copies must be wiped on every code path. PanicPin.register
            // and KeyManager.unlock each wipe their own input internally.
            val unlockCopy = passphrase.copyOf()
            val regCopy: CharArray? = if (panicPinChars != null && panicPinChars.isNotEmpty()) {
                passphrase.copyOf()
            } else null
            try {
                keyManager.setupNew(passphrase)
                if (panicPinChars != null && panicPinChars.isNotEmpty() && regCopy != null) {
                    panicPin.register(panicPinChars, regCopy)
                }
                val result = keyManager.unlock(unlockCopy)
                result.fold(
                    onSuccess = { dek ->
                        currentFailCount = 0
                        authState.setFailCount(0)
                        val now = clock.millis()
                        authState.setLastAuthSuccessEpoch(now)
                        attestedClock?.write(now)
                        onUnlocked(dek)
                        _state.value = LockState.Unlocked
                    },
                    onFailure = {
                        // Should not happen — we just wrote the matching wrap.
                        // Fall back to Locked with no backoff so the user can retry.
                        unlockCopy.wipe()
                        _state.value = LockState.Locked(failCount = 0, backoffSeconds = 0)
                    },
                )
            } catch (t: Throwable) {
                unlockCopy.wipe()
                regCopy?.wipe()
                _state.value = LockState.Locked(failCount = 0, backoffSeconds = 0)
                throw t
            }
        }
    }

    /**
     * Lifecycle hook — Phase 6 wiring (LifecycleLock) calls this when the
     * lock-timer fires. Drops the in-memory DEK reference (held by the App
     * layer; this ViewModel does not retain it) by transitioning to Locked.
     *
     * Review B3 — re-resolve setup state on every transition so a NUCLEAR
     * wipe (which deletes the wrapped DEK + Keystore alias) routes the user
     * to [LockState.Setup] instead of leaving them stuck on the AuthGate
     * with no DEK to compare against.
     */
    suspend fun enterBackground() {
        _state.value = if (keyManager.isSetupComplete()) {
            LockState.Locked(failCount = currentFailCount, backoffSeconds = 0)
        } else {
            LockState.Setup
        }
    }

    /** Foreground does not auto-unlock; the user must always re-enter the passphrase. */
    fun enterForeground(): Unit = Unit

    /**
     * Plan §8.1 — wizard "back to login" affordance after a migration failure.
     * Drops the [LockState.Migrating] error state and re-locks the gate so
     * the user can re-authenticate (which kicks off a fresh migration retry).
     */
    fun dismissMigrationError() {
        if (state.value is LockState.Migrating) {
            _state.value = LockState.Locked(failCount = currentFailCount, backoffSeconds = 0)
        }
    }

    companion object {
        /**
         * How long the panic path keeps showing the fake "Unlocked" state before
         * the crypto-erase fires. Long enough to look like a normal unlock to
         * a coercer; short enough that any real workload doesn't get to start.
         */
        const val PANIC_FAKE_UNLOCK_MS: Long = 200L

        /**
         * Production [ViewModelProvider.Factory] wiring for [MainActivity].
         *
         * Builds the real dependency graph:
         *  - [KeyManager] — Argon2id + envelope + Keystore (Phase 2.1)
         *  - [WipeManager] — wipe ladder (Phase 5.4 stub; Phase 7.1 lands real)
         *  - [PanicPin] — panic-PIN compare (Phase 5.4 stub; Phase 7.3 lands real)
         *  - `app.settings` — plaintext auth-state DataStore (Phase 4.1)
         *
         * `onUnlocked` installs the encrypted database with the recovered DEK
         * and wipes the in-process copy. SQLCipher's open helper internally
         * copies the bytes (clearPassphrase = true) so the wipe is safe.
         *
         * JVM unit tests bypass this factory and pass fakes directly to the
         * primary constructor — no Keystore / DataStore on the JVM.
         */
        fun factory(app: App): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                // Plan §10.2 / review B9 — read the cached calibrated params
                // resolved during App.onCreate's applicationScope job. The
                // first call after process start blocks on the job's
                // completion; subsequent calls (Activity recreate, theme
                // change) hit the @Volatile cache with no main-thread work.
                val params = app.awaitArgon2Params()
                val km = KeyManager(app, params = params)
                return AuthViewModel(
                    keyManager = km,
                    wipeManager = WipeManager(
                        context = app,
                        keyManager = km,
                        onLock = {
                            app.closeAndZeroizeDatabase()
                            app.settings.unbindSecurePrefs()
                        },
                        onUiLock = { app.emitLockSignal() },
                    ),
                    panicPin = PanicPin(
                        store = app.settings,
                        // Review B2 — derive uses the same calibrated params
                        // as KeyManager so register-time and match-time hashes
                        // agree on calibrated devices.
                        derive = PanicPin.productionDerive(params),
                    ),
                    authState = app.settings,
                    onUnlocked = { dek ->
                        app.installDatabase(dek.toByteArray())
                        dek.wipe()
                    },
                    lockSignal = app.lockSignal,
                    attestedClock = KeystoreAttestedClock(app),
                    migration = PlaintextToCipherMigration(app),
                ) as T
            }
        }
    }
}
