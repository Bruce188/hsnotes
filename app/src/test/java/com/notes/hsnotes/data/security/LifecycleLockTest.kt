package com.notes.hsnotes.data.security

import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * JVM unit-test coverage for [LifecycleLock]. Plan §6.1 Tests block.
 *
 * Time is driven by [TestScope]'s virtual clock — no real-time delays — so
 * the suite runs in milliseconds regardless of the configured timeout.
 *
 * The actual `ProcessLifecycleOwner.get().lifecycle.addObserver(...)` glue
 * lives in `App.onCreate` and is covered by `assembleDebug` only (see plan
 * `Context:` block).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LifecycleLockTest {

    /** Lifecycle library hands a real owner to onStop/onStart; body never reads its lifecycle. */
    private object FakeOwner : LifecycleOwner {
        override val lifecycle: Lifecycle
            get() = throw UnsupportedOperationException("not used by LifecycleLock")
    }

    @Test
    fun onStop_starts_lockTimer() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val scope = TestScope(dispatcher)
        var fired = 0
        val lock = LifecycleLock(
            scope = scope,
            timeoutMsProvider = { 60_000L },
            onTimeout = { fired += 1 },
        )

        lock.onStop(FakeOwner)
        scope.runCurrent()
        scope.advanceTimeBy(59_999L)
        scope.runCurrent()

        // Timer is running but has not fired yet.
        assertEquals(0, fired)
    }

    @Test
    fun timer_expiry_calls_enterBackground_on_authViewModel() = runTest {
        // The "enterBackground on AuthViewModel" wiring lives in App.onCreate:
        // app.onTimeout = { closeAndZeroizeDatabase(); _lockSignal.emit(Unit) }
        // and AuthViewModel collects lockSignal → enterBackground(). Here we
        // only verify the LifecycleLock half — that the callback fires after
        // the configured delay.
        val dispatcher = StandardTestDispatcher(testScheduler)
        val scope = TestScope(dispatcher)
        var fired = 0
        val lock = LifecycleLock(
            scope = scope,
            timeoutMsProvider = { 60_000L },
            onTimeout = { fired += 1 },
        )

        lock.onStop(FakeOwner)
        scope.advanceTimeBy(60_001L)
        scope.runCurrent()

        assertEquals(1, fired)
    }

    @Test
    fun foreground_before_timer_expiry_cancels_timer() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val scope = TestScope(dispatcher)
        var fired = 0
        val lock = LifecycleLock(
            scope = scope,
            timeoutMsProvider = { 60_000L },
            onTimeout = { fired += 1 },
        )

        lock.onStop(FakeOwner)
        scope.runCurrent()
        scope.advanceTimeBy(30_000L)
        scope.runCurrent()
        // User returns to foreground BEFORE timeout — must cancel.
        lock.onStart(FakeOwner)
        scope.advanceTimeBy(60_000L)
        scope.runCurrent()

        assertEquals(0, fired)
    }

    @Test
    fun configurable_timeout_default_60s_when_pref_unset() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val scope = TestScope(dispatcher)
        var fired = 0
        // Provider mirrors what Settings.lockTimeoutMs returns when the pref
        // is unset — 60_000L per the data class default.
        val lock = LifecycleLock(
            scope = scope,
            timeoutMsProvider = { LifecycleLock.DEFAULT_TIMEOUT_MS },
            onTimeout = { fired += 1 },
        )

        lock.onStop(FakeOwner)
        scope.advanceTimeBy(59_999L)
        scope.runCurrent()
        assertEquals(0, fired)
        scope.advanceTimeBy(2L)
        scope.runCurrent()
        assertEquals(1, fired)
    }

    @Test
    fun custom_timeout_from_securePrefs_overrides_default() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val scope = TestScope(dispatcher)
        var fired = 0
        val lock = LifecycleLock(
            scope = scope,
            timeoutMsProvider = { 30_000L }, // simulate user-configured 30s.
            onTimeout = { fired += 1 },
        )

        lock.onStop(FakeOwner)
        scope.advanceTimeBy(29_999L)
        scope.runCurrent()
        assertEquals(0, fired)
        scope.advanceTimeBy(2L)
        scope.runCurrent()
        assertEquals(1, fired)
    }
}
