package com.notes.hsnotes

import android.app.Application
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.lifecycleScope
import com.notes.hsnotes.data.db.AppDatabase
import com.notes.hsnotes.data.db.LockedException
import com.notes.hsnotes.data.repo.NotesRepository
import com.notes.hsnotes.data.security.AntiForensics
import com.notes.hsnotes.data.security.Argon2Calibrator
import com.notes.hsnotes.data.security.Argon2Params
import com.notes.hsnotes.data.security.DeadManCheck
import com.notes.hsnotes.data.security.LifecycleLock
import com.notes.hsnotes.data.settings.SettingsStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

class App : Application() {

    @Volatile private var _database: AppDatabase? = null
    @Volatile private var _repository: NotesRepository? = null

    /**
     * Throws [LockedException] before [installDatabase] has been called.
     * Phase 5 (AuthGate) ensures no UI surface accesses this pre-unlock.
     */
    val database: AppDatabase
        get() = _database ?: throw LockedException()

    /**
     * Throws [LockedException] before [installDatabase] has been called.
     * Phase 5 (AuthGate) ensures no UI surface accesses this pre-unlock.
     */
    val repository: NotesRepository
        get() = _repository ?: throw LockedException()

    val settings: SettingsStore by lazy { SettingsStore(this) }

    /**
     * Process-wide background scope. Survives Activity recreates. Used for
     * one-shot startup work (calibrator, language) that must complete but
     * does NOT need to block the main thread before the first frame.
     */
    private val applicationScope: CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Plan §10.2 / review B8 — Argon2 calibration runs on [applicationScope]
     * and produces the [Argon2Params] consumers should use. Awaiting blocks
     * only on the FIRST consumer call after process start (cold boot).
     * Subsequent calls hit the cached [argon2Params] field.
     */
    @Volatile
    @Suppress("ForbiddenMethodCall")  // Review B10: defensive seed before applicationScope.async resolves.
    var argon2Params: Argon2Params = Argon2Params.default()
        private set

    private lateinit var argon2ReadyJob: Deferred<Argon2Params>

    /**
     * Block until [argon2ReadyJob] completes; cache the result on
     * [argon2Params] for subsequent reads. Safe to call on the main thread
     * — typical wait is < ~1s on first cold boot, < 10ms thereafter (the
     * calibrator short-circuits to a single DataStore read).
     *
     * Review V-N2 — fail-closed: if the async job threw (DataStore corrupt,
     * native Argon2 OOM during probe), [Argon2Params.default] is the safe
     * fallback. The Deferred is wrapped in [runCatching] in [onCreate] so it
     * never completes exceptionally; this catch is the second line of defense
     * (e.g. cancelled job, dispatcher shutdown).
     */
    fun awaitArgon2Params(): Argon2Params {
        if (!::argon2ReadyJob.isInitialized) return argon2Params
        if (argon2ReadyJob.isCompleted) return argon2Params
        return try {
            val resolved = runBlocking { argon2ReadyJob.await() }
            argon2Params = resolved
            resolved
        } catch (_: Throwable) {
            // Never crash a consumer because calibration failed — the seed
            // default (256 MiB / t=4 / p=2) is always safe to use.
            argon2Params
        }
    }

    /**
     * Lifecycle-driven idle lock signal. Plan §6.1 — emitted when the lock
     * timer fires. [com.notes.hsnotes.ui.auth.AuthViewModel] collects
     * this and transitions to [com.notes.hsnotes.ui.auth.LockState.Locked]
     * via `enterBackground()`.
     */
    private val _lockSignal = MutableSharedFlow<Unit>(replay = 0, extraBufferCapacity = 1)
    val lockSignal: SharedFlow<Unit> = _lockSignal.asSharedFlow()

    /**
     * Emit on [lockSignal]. Called from [com.notes.hsnotes.data.security.WipeManager]
     * (Phase 7.1) for [com.notes.hsnotes.data.security.WipeLevel.SOFT] /
     * [com.notes.hsnotes.data.security.WipeLevel.LOCK] /
     * [com.notes.hsnotes.data.security.WipeLevel.NUCLEAR] paths so the
     * auth gate flips back to Locked after a destructive operation.
     */
    suspend fun emitLockSignal() {
        _lockSignal.emit(Unit)
    }

    /**
     * Open the encrypted database with [dek] and build the repository.
     *
     * The caller retains ownership of [dek] and is responsible for wiping it
     * after this returns. SQLCipher's [SupportOpenHelperFactory] internally
     * copies [dek] (clearPassphrase = true) so the caller's bytes are not
     * mutated here.
     *
     * Idempotent — calling twice closes the prior instance first.
     *
     * Plan §3.1 — invoked by `AuthViewModel` after successful unlock (Phase 5).
     */
    @Synchronized
    fun installDatabase(dek: ByteArray) {
        closeAndZeroizeDatabaseLocked()
        val db = AppDatabase.build(this, dek)
        _database = db
        _repository = NotesRepository.fromDatabase(database = db)
    }

    /**
     * Close the encrypted database and drop all references. After this call,
     * [database] and [repository] throw [LockedException] until the next
     * [installDatabase].
     *
     * Plan §3.1 — invoked from `LifecycleLock` (Phase 6) on app-background.
     */
    @Synchronized
    fun closeAndZeroizeDatabase() {
        closeAndZeroizeDatabaseLocked()
    }

    private fun closeAndZeroizeDatabaseLocked() {
        _repository = null
        _database?.close()
        _database = null
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        // Plan §7.2 — DeadManCheck MUST be the first user-code line after super.
        // If the 14-day window has elapsed (or both timestamp sources are
        // tampered), this triggers cryptoErase before any UI / database / DEK
        // material is touched. runBlocking is safe here: the entire onCreate
        // path is already a one-shot startup hook, and DeadManCheck does at
        // most a single Keystore HMAC + a DataStore read.
        runBlocking { DeadManCheck.run(this@App) }
        // Plan §1.4 — Anti-forensics one-shot init. Idempotent guard inside.
        AntiForensics.init(this)
        // Plan §10.2 / review B8 — Argon2 calibration moved off the main
        // thread. The async block runs the (idempotent) probe + reads the
        // tuned `m`. Consumers (AuthViewModel.factory, SettingsViewModel)
        // read [argon2Params] via [awaitArgon2Params]; only the FIRST consumer
        // call after process start blocks while the job completes.
        argon2ReadyJob = applicationScope.async {
            // Review V-N2 — wrap so the Deferred never completes exceptionally.
            // A calibration failure must not crash MainActivity composition;
            // the default params are always safe (security floor unchanged).
            //
            // Review v3-N1 — explicit Throwable catch instead of runCatching:
            // runCatching swallows CancellationException, which would mask
            // structured-cancellation propagation if applicationScope is ever
            // cancelled mid-calibration. Cancellation must rethrow; only real
            // calibration failures fall back.
            val resolved = try {
                Argon2Calibrator.ensureCalibrated(settings)
                Argon2Params.calibratedOrDefault(settings)
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                @Suppress("ForbiddenMethodCall")  // Review B10 / V-N2: explicit safe fallback.
                Argon2Params.default()
            }
            argon2Params = resolved
            resolved
        }
        // Review V-N3/P-1 — language read moved off the main thread. DataStore
        // proto-init + first-emission can take 50-300ms on slow eMMC; cold
        // boot must not pay that on the UI thread before the first frame. The
        // user briefly sees the system-default locale before the persisted
        // override takes effect, which is acceptable: the Setup / AuthGate
        // strings exist in every supported locale and re-render automatically
        // when AppCompatDelegate.setApplicationLocales fires.
        applicationScope.async { applyPersistedLanguage() }
        registerLifecycleLock()
    }

    /**
     * Plan §6.1 — register the idle-lock observer on the process-wide lifecycle.
     *
     * The timeout source is [SettingsStore.flow] `.lockTimeoutMs`, which:
     *  - returns the plaintext-store value (default 60_000L) before unlock;
     *  - returns the SecurePrefs-stored override after unlock (Phase 4 binding).
     *
     * On timeout we close the encrypted database (drops the in-memory DEK
     * reference held by SQLCipher), unbind SecurePrefs (no-op if unbound),
     * and emit on [lockSignal] so the active [com.notes.hsnotes.ui.auth.AuthViewModel]
     * can transition the UI back to [com.notes.hsnotes.ui.auth.LockState.Locked].
     */
    private fun registerLifecycleLock() {
        val owner = ProcessLifecycleOwner.get()
        val lock = LifecycleLock(
            scope = owner.lifecycleScope,
            timeoutMsProvider = { settings.flow.first().lockTimeoutMs },
            onTimeout = {
                closeAndZeroizeDatabase()
                settings.unbindSecurePrefs()
                _lockSignal.emit(Unit)
            },
        )
        owner.lifecycle.addObserver(lock)
    }

    /**
     * Review V-N3/P-1 — now suspending and dispatched onto [applicationScope]
     * from [onCreate]. Reads the persisted language and applies it via
     * [AppCompatDelegate]. Off-main; the user may see the system default for
     * a frame or two before the override lands.
     */
    private suspend fun applyPersistedLanguage() {
        val tag = settings.flow.first().language
        if (!tag.isNullOrBlank()) {
            // AppCompatDelegate.setApplicationLocales touches Activity stack
            // state — hop to Main to keep the existing semantics regardless
            // of where the caller dispatcher resolves.
            kotlinx.coroutines.withContext(Dispatchers.Main) {
                AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))
            }
        }
    }

    companion object {
        lateinit var instance: App
            private set
    }
}
