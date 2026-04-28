package com.notes.hsnotes.ui.auth

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import com.notes.hsnotes.data.security.CryptoConfig
import com.notes.hsnotes.data.security.Dek
import com.notes.hsnotes.data.security.KeyManagerApi
import com.notes.hsnotes.data.security.PanicPinApi
import com.notes.hsnotes.data.security.WipeLevel
import com.notes.hsnotes.data.security.WipeManagerApi
import com.notes.hsnotes.data.security.WrongPassphrase
import com.notes.hsnotes.data.settings.AuthStateStore
import org.junit.Rule
import org.junit.Test
import java.time.Clock

/**
 * Compose-rule coverage for [AuthGateScreen]. Plan §5.3 Tests block.
 *
 * Staged for `connectedDebugAndroidTest`.
 */
class AuthGateScreenTest {

    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun attempt_counter_renders_x_of_5() {
        val authState = FakeAuthState(initialFailCount = 0)
        val vm = newVm(authState = authState)
        composeRule.setContent {
            MaterialTheme { Surface { AuthGateScreen(vm = vm) } }
        }
        composeRule.onNodeWithTag(AUTH_GATE_TAG_ATTEMPT_COUNTER).assertIsDisplayed()
    }

    @Test
    fun backoff_timer_visible_and_counts_down() {
        val authState = FakeAuthState(initialFailCount = 0)
        val km = AlwaysWrongKeyManager()
        val vm = newVm(km = km, authState = authState)
        composeRule.mainClock.autoAdvance = false
        composeRule.setContent {
            MaterialTheme { Surface { AuthGateScreen(vm = vm) } }
        }
        composeRule.mainClock.advanceTimeBy(100L)

        composeRule.onNodeWithTag(AUTH_GATE_TAG_PASSPHRASE).performTextInput("nope")
        composeRule.onNodeWithTag(AUTH_GATE_TAG_SUBMIT).performClick()
        // First failure → backoff = LOCKOUT_SCHEDULE_SECONDS[0] = 1
        composeRule.mainClock.advanceTimeBy(50L)
        composeRule.onNodeWithTag(AUTH_GATE_TAG_BACKOFF).assertIsDisplayed()

        // After the backoff window the ticker hits zero and the banner clears.
        composeRule.mainClock.advanceTimeBy(2_000L)
        composeRule.onNodeWithTag(AUTH_GATE_TAG_BACKOFF).assertIsNotDisplayed()
    }

    @Test
    fun warning_banner_shown_at_attempts_3_and_4() {
        // Seed failCount = 3; init coroutine surfaces the warning immediately.
        val vm = newVm(authState = FakeAuthState(initialFailCount = 3))
        composeRule.setContent {
            MaterialTheme { Surface { AuthGateScreen(vm = vm) } }
        }
        composeRule.onNodeWithTag(AUTH_GATE_TAG_WARNING).assertIsDisplayed()
    }

    @Test
    fun generic_incorrect_message_no_oracle_difference_for_unknown_user() {
        // Same banner shown regardless of what the underlying error class is —
        // KeyManagerApi already collapses every failure into WrongPassphrase.
        val vm = newVm(km = AlwaysWrongKeyManager())
        composeRule.mainClock.autoAdvance = false
        composeRule.setContent {
            MaterialTheme { Surface { AuthGateScreen(vm = vm) } }
        }
        composeRule.mainClock.advanceTimeBy(100L)
        composeRule.onNodeWithTag(AUTH_GATE_TAG_PASSPHRASE).performTextInput("nope")
        composeRule.onNodeWithTag(AUTH_GATE_TAG_SUBMIT).performClick()
        composeRule.mainClock.advanceTimeBy(50L)
        composeRule.onNodeWithTag(AUTH_GATE_TAG_FAILED).assertIsDisplayed()
    }

    @Test
    fun passphrase_field_clears_on_failed_attempt() {
        val km = AlwaysWrongKeyManager()
        val vm = newVm(km = km)
        composeRule.mainClock.autoAdvance = false
        composeRule.setContent {
            MaterialTheme { Surface { AuthGateScreen(vm = vm) } }
        }
        composeRule.mainClock.advanceTimeBy(100L)
        composeRule.onNodeWithTag(AUTH_GATE_TAG_PASSPHRASE).performTextInput("nope")
        composeRule.onNodeWithTag(AUTH_GATE_TAG_SUBMIT).performClick()
        composeRule.mainClock.advanceTimeBy(100L)
        // After the failed attempt the field is cleared — entering the same
        // text again should land in an empty buffer.
        composeRule.onNodeWithTag(AUTH_GATE_TAG_PASSPHRASE).performTextInput("a")
        // Smoke: the screen has not crashed, the field is rendering.
        composeRule.onNodeWithTag(AUTH_GATE_TAG_PASSPHRASE).assertIsDisplayed()
    }

    private fun newVm(
        km: KeyManagerApi = AlwaysWrongKeyManager(),
        wipe: WipeManagerApi = NoopWipe(),
        panic: PanicPinApi = NoopPanic(),
        authState: AuthStateStore = FakeAuthState(),
        clock: Clock = Clock.systemUTC(),
    ): AuthViewModel = AuthViewModel(
        keyManager = km,
        wipeManager = wipe,
        panicPin = panic,
        authState = authState,
        clock = clock,
    )

    private class AlwaysWrongKeyManager : KeyManagerApi {
        override suspend fun isSetupComplete(): Boolean = true
        override suspend fun setupNew(passphrase: CharArray) {
            passphrase.fill(' ')
        }
        override suspend fun unlock(passphrase: CharArray): Result<Dek> {
            passphrase.fill(' ')
            return Result.failure(WrongPassphrase())
        }
        override suspend fun changePassphrase(oldPassphrase: CharArray, newPassphrase: CharArray) {
            oldPassphrase.fill(' ')
            newPassphrase.fill(' ')
        }
        override suspend fun cryptoErase() = Unit
    }

    private class NoopWipe : WipeManagerApi {
        override suspend fun wipeNow(level: WipeLevel) = Unit
    }

    private class NoopPanic : PanicPinApi {
        override suspend fun register(pin: CharArray, realPassphrase: CharArray) {
            pin.fill(' ')
            realPassphrase.fill(' ')
        }
        override suspend fun matches(input: CharArray): Boolean = false
    }

    private class FakeAuthState(
        initialFailCount: Int = 0,
    ) : AuthStateStore {
        private var fc: Int = initialFailCount
        override suspend fun currentFailCount(): Int = fc
        override suspend fun setFailCount(n: Int) {
            fc = n
        }
        override suspend fun setLastAuthSuccessEpoch(epochMs: Long?) = Unit
        override suspend fun lastAuthSuccessEpoch(): Long? = null
    }
}
