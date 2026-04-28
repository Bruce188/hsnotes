package com.notes.hsnotes.ui.auth

import com.notes.hsnotes.data.security.CryptoConfig
import com.notes.hsnotes.data.security.Dek
import com.notes.hsnotes.data.security.KeyManagerApi
import com.notes.hsnotes.data.security.PanicPinApi
import com.notes.hsnotes.data.security.WipeLevel
import com.notes.hsnotes.data.security.WipeManagerApi
import com.notes.hsnotes.data.security.WrongPassphrase
import com.notes.hsnotes.data.settings.AuthStateStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * JVM unit-test coverage for [AuthViewModel]. Plan §5.1 Tests block.
 *
 * The ViewModel depends on three security interfaces ([KeyManagerApi],
 * [WipeManagerApi], [PanicPinApi]) plus the narrow [AuthStateStore] surface
 * SettingsStore implements. Every dependency is replaced here with an
 * in-memory fake so the test runs purely on the JVM (no Android Context, no
 * Argon2 native libs, no DataStore file IO).
 *
 * The ViewModel uses `viewModelScope` (Main-bound) for all coroutines, so the
 * suite installs a [StandardTestDispatcher] as Main. `runCurrent()` and
 * `advanceUntilIdle()` are then the two knobs needed to step state.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AuthViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    // -------------------------------------------------------------------------
    // initial state
    // -------------------------------------------------------------------------

    @Test
    fun initialState_is_Setup_when_keyManager_isSetupComplete_false() = runTest(testDispatcher) {
        val vm = newVm(km = FakeKeyManager(setupComplete = false))
        advanceUntilIdle()
        assertEquals(LockState.Setup, vm.state.value)
    }

    @Test
    fun initialState_is_Locked_when_keyManager_isSetupComplete_true() = runTest(testDispatcher) {
        val auth = FakeAuthState(initialFailCount = 2)
        val vm = newVm(km = FakeKeyManager(setupComplete = true), authState = auth)
        advanceUntilIdle()
        assertEquals(LockState.Locked(failCount = 2, backoffSeconds = 0), vm.state.value)
    }

    // -------------------------------------------------------------------------
    // unlock — happy path
    // -------------------------------------------------------------------------

    @Test
    fun unlock_correctPassphrase_transitions_Locked_to_Unlocking_to_Unlocked() = runTest(testDispatcher) {
        val km = FakeKeyManager(setupComplete = true, correctPassphrase = "secret".toCharArray())
        val vm = newVm(km = km)
        advanceUntilIdle()
        assertTrue(vm.state.value is LockState.Locked)

        vm.unlock("secret".toCharArray())
        advanceUntilIdle()

        assertEquals(LockState.Unlocked, vm.state.value)
        assertEquals(1, km.unlockCalls)
    }

    // -------------------------------------------------------------------------
    // unlock — failure increments failCount, stays Locked
    // -------------------------------------------------------------------------

    @Test
    fun unlock_wrongPassphrase_remains_Locked_and_increments_failCount() = runTest(testDispatcher) {
        val km = FakeKeyManager(setupComplete = true, correctPassphrase = "secret".toCharArray())
        val auth = FakeAuthState()
        val wipe = FakeWipeManager()
        val vm = newVm(km = km, wipe = wipe, authState = auth)
        advanceUntilIdle()

        vm.unlock("wrong".toCharArray())
        advanceUntilIdle()

        val s = vm.state.value
        assertTrue("expected Locked, was $s", s is LockState.Locked)
        s as LockState.Locked
        assertEquals(1, s.failCount)
        assertEquals(CryptoConfig.LOCKOUT_SCHEDULE_SECONDS[0], s.backoffSeconds)
        assertEquals(1, auth.failCount)
        assertTrue("wipe must not fire on first miss", wipe.calls.isEmpty())
    }

    // -------------------------------------------------------------------------
    // wipe ladder
    // -------------------------------------------------------------------------

    @Test
    fun fifth_consecutive_failure_transitions_to_Wiped() = runTest(testDispatcher) {
        val km = FakeKeyManager(setupComplete = true, correctPassphrase = "secret".toCharArray())
        val auth = FakeAuthState()
        val wipe = FakeWipeManager()
        val vm = newVm(km = km, wipe = wipe, authState = auth)
        advanceUntilIdle()

        repeat(CryptoConfig.WIPE_FAIL_THRESHOLD) {
            vm.unlock("wrong".toCharArray())
            advanceUntilIdle()
        }

        assertEquals(LockState.Wiped, vm.state.value)
        assertEquals(CryptoConfig.WIPE_FAIL_THRESHOLD, auth.failCount)
        assertEquals(listOf(WipeLevel.CRYPTO_ERASE), wipe.calls)
    }

    // -------------------------------------------------------------------------
    // panic PIN
    // -------------------------------------------------------------------------

    @Test
    fun panicPin_match_emits_PanicSpinner_then_Wiped_in_background() = runTest(testDispatcher) {
        val panic = FakePanicPin(matchValue = true)
        val wipe = FakeWipeManager()
        val km = FakeKeyManager(setupComplete = true, correctPassphrase = "secret".toCharArray())
        val vm = newVm(km = km, wipe = wipe, panic = panic)
        advanceUntilIdle()

        vm.unlock("99999".toCharArray())
        // Run the panic-branch coroutine until it reaches the first delay() —
        // by then the fake-unlock state is published and the wipe has not fired.
        runCurrent()
        // Review V-N1 — must NOT be Unlocked: that would mount the post-unlock
        // NavHost, which reads `app.repository`, which crashes pre-installDB.
        // PanicSpinner renders the same UI as Unlocking from the user POV.
        assertEquals(LockState.PanicSpinner, vm.state.value)
        assertTrue("wipe must wait for delay()", wipe.calls.isEmpty())

        // Cross the fake-unlock window — wipe + Wiped must follow.
        advanceTimeBy(AuthViewModel.PANIC_FAKE_UNLOCK_MS + 1L)
        advanceUntilIdle()

        assertEquals(LockState.Wiped, vm.state.value)
        assertEquals(listOf(WipeLevel.CRYPTO_ERASE), wipe.calls)
        // Panic path must NOT touch the real KeyManager — that would expose timing.
        assertEquals(0, km.unlockCalls)
    }

    // -------------------------------------------------------------------------
    // backoff schedule
    // -------------------------------------------------------------------------

    @Test
    fun backoff_seconds_follow_CryptoConfig_schedule() = runTest(testDispatcher) {
        val km = FakeKeyManager(setupComplete = true, correctPassphrase = "secret".toCharArray())
        val vm = newVm(km = km)
        advanceUntilIdle()

        val schedule = CryptoConfig.LOCKOUT_SCHEDULE_SECONDS
        // Step through THRESHOLD-1 misses so we stop short of the wipe.
        for (i in 0 until CryptoConfig.WIPE_FAIL_THRESHOLD - 1) {
            vm.unlock("wrong".toCharArray())
            advanceUntilIdle()
            val s = vm.state.value
            assertTrue("attempt ${i + 1}: expected Locked, was $s", s is LockState.Locked)
            s as LockState.Locked
            val expectedIdx = i.coerceAtMost(schedule.size - 1)
            assertEquals(
                "attempt ${i + 1} backoff",
                schedule[expectedIdx],
                s.backoffSeconds,
            )
            assertEquals(i + 1, s.failCount)
        }
    }

    // -------------------------------------------------------------------------
    // success resets the counter + records the auth-success epoch
    // -------------------------------------------------------------------------

    @Test
    fun successful_unlock_resets_failCount_to_zero() = runTest(testDispatcher) {
        val km = FakeKeyManager(setupComplete = true, correctPassphrase = "secret".toCharArray())
        val auth = FakeAuthState(initialFailCount = 3)
        val fixedClock = Clock.fixed(Instant.ofEpochMilli(1_700_000_000_000L), ZoneOffset.UTC)
        val vm = newVm(km = km, authState = auth, clock = fixedClock)
        advanceUntilIdle()
        // Bump to 4 with one more miss — still under threshold.
        vm.unlock("wrong".toCharArray())
        advanceUntilIdle()
        assertEquals(4, auth.failCount)
        assertNull(auth.lastEpoch)

        vm.unlock("secret".toCharArray())
        advanceUntilIdle()

        assertEquals(LockState.Unlocked, vm.state.value)
        assertEquals(0, auth.failCount)
        assertEquals(1_700_000_000_000L, auth.lastEpoch)
    }

    // -------------------------------------------------------------------------
    // helpers + fakes
    // -------------------------------------------------------------------------

    private fun newVm(
        km: KeyManagerApi = FakeKeyManager(setupComplete = true),
        wipe: WipeManagerApi = FakeWipeManager(),
        panic: PanicPinApi = FakePanicPin(),
        authState: AuthStateStore = FakeAuthState(),
        clock: Clock = Clock.systemUTC(),
    ): AuthViewModel = AuthViewModel(
        keyManager = km,
        wipeManager = wipe,
        panicPin = panic,
        authState = authState,
        clock = clock,
    )
}

private class FakeKeyManager(
    private val setupComplete: Boolean,
    private val correctPassphrase: CharArray = CharArray(0),
    private val dek: Dek = Dek(ByteArray(32)),
) : KeyManagerApi {
    var unlockCalls: Int = 0
        private set

    override suspend fun isSetupComplete(): Boolean = setupComplete

    override suspend fun setupNew(passphrase: CharArray) {
        passphrase.fill(' ')
    }

    override suspend fun unlock(passphrase: CharArray): Result<Dek> {
        unlockCalls += 1
        val matches = correctPassphrase.size == passphrase.size &&
            correctPassphrase.indices.all { i -> correctPassphrase[i] == passphrase[i] }
        passphrase.fill(' ')
        return if (matches) Result.success(dek) else Result.failure(WrongPassphrase())
    }

    override suspend fun changePassphrase(oldPassphrase: CharArray, newPassphrase: CharArray) {
        oldPassphrase.fill(' ')
        newPassphrase.fill(' ')
    }

    override suspend fun cryptoErase() = Unit
}

private class FakeWipeManager : WipeManagerApi {
    val calls: MutableList<WipeLevel> = mutableListOf()
    override suspend fun wipeNow(level: WipeLevel) {
        calls += level
    }
}

private class FakePanicPin(
    private val matchValue: Boolean = false,
) : PanicPinApi {
    var registered: CharArray? = null
        private set
    var registeredAgainstPassphrase: CharArray? = null
        private set

    override suspend fun register(pin: CharArray, realPassphrase: CharArray) {
        registered = pin.copyOf()
        registeredAgainstPassphrase = realPassphrase.copyOf()
        pin.fill(' ')
        realPassphrase.fill(' ')
    }

    override suspend fun matches(input: CharArray): Boolean = matchValue
}

private class FakeAuthState(
    initialFailCount: Int = 0,
) : AuthStateStore {
    var failCount: Int = initialFailCount
    var lastEpoch: Long? = null

    override suspend fun currentFailCount(): Int = failCount
    override suspend fun setFailCount(n: Int) {
        require(n >= 0)
        failCount = n
    }
    override suspend fun setLastAuthSuccessEpoch(epochMs: Long?) {
        lastEpoch = epochMs
    }
    override suspend fun lastAuthSuccessEpoch(): Long? = lastEpoch
}
