package com.notes.hsnotes.data.security

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Lifecycle-driven idle lock. Plan §6.1.
 *
 * Behaviour:
 *  - On `onStop` (the app went to background) start a coroutine that delays
 *    [timeoutMsProvider] milliseconds and then invokes [onTimeout]. Production
 *    [onTimeout] zeroizes the in-memory DEK, unbinds SecurePrefs, and signals
 *    [com.notes.hsnotes.ui.auth.AuthViewModel] to transition back to
 *    [com.notes.hsnotes.ui.auth.LockState.Locked].
 *  - On `onStart` (the app returned to foreground BEFORE the timer fired)
 *    cancel the pending job — the user does not need to re-authenticate.
 *
 * Decoupled from `AuthViewModel` and `App` for testability — the scope, the
 * timeout source, and the timeout action are all injected. JVM tests use a
 * `TestScope` + virtual time and observe the callback directly. The owner
 * object passed to [onStart] / [onStop] is unused inside the body; the
 * lifecycle library always supplies a non-null instance.
 */
class LifecycleLock(
    private val scope: CoroutineScope,
    private val timeoutMsProvider: suspend () -> Long,
    private val onTimeout: suspend () -> Unit,
) : DefaultLifecycleObserver {

    @Volatile
    private var pendingJob: Job? = null

    override fun onStop(owner: LifecycleOwner) {
        // Cancel any in-flight timer (defensive — onStop should be paired
        // with onStart but the lifecycle library may emit redundant events).
        pendingJob?.cancel()
        pendingJob = scope.launch {
            val timeoutMs = timeoutMsProvider()
            delay(timeoutMs)
            // Re-check the slot: a concurrent onStart could have nulled it.
            // If still set, fire the callback.
            if (pendingJob != null) {
                onTimeout()
            }
            pendingJob = null
        }
    }

    override fun onStart(owner: LifecycleOwner) {
        pendingJob?.cancel()
        pendingJob = null
    }

    companion object {
        /** Plan-mandated default — overridable via SecurePrefs LOCK_TIMEOUT_MS. */
        const val DEFAULT_TIMEOUT_MS: Long = 60_000L
    }
}
