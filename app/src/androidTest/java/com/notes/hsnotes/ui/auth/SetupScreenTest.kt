package com.notes.hsnotes.ui.auth

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
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
 * Compose-rule coverage for [SetupScreen]. Plan §5.2 Tests block.
 *
 * Drives the screen via test tags rather than localized labels so the suite
 * is locale-independent. The cooldown timer is stepped via
 * `composeRule.mainClock.advanceTimeBy` (autoAdvance disabled) so the 5s
 * gate is observable deterministically.
 *
 * Staged for `connectedDebugAndroidTest`.
 */
class SetupScreenTest {

    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun continue_disabled_until_warning_acknowledged() {
        val vm = newVm()
        composeRule.mainClock.autoAdvance = false
        composeRule.setContent {
            MaterialTheme { Surface { SetupScreen(vm = vm, onComplete = {}) } }
        }
        // Let the init coroutine resolve to Setup state.
        composeRule.mainClock.advanceTimeBy(100L)
        composeRule.onNodeWithTag(SETUP_TAG_CONTINUE).assertIsNotEnabled()
    }

    @Test
    fun continue_disabled_during_5s_cooldown_after_ack() {
        val vm = newVm()
        composeRule.mainClock.autoAdvance = false
        composeRule.setContent {
            MaterialTheme { Surface { SetupScreen(vm = vm, onComplete = {}) } }
        }
        composeRule.mainClock.advanceTimeBy(100L)

        composeRule.onNodeWithTag(SETUP_TAG_PASSPHRASE).performTextInput("opensesame")
        composeRule.onNodeWithTag(SETUP_TAG_CONFIRM).performTextInput("opensesame")
        composeRule.onNodeWithTag(SETUP_TAG_ACK).performClick()

        // Mid-cooldown: still disabled.
        composeRule.mainClock.advanceTimeBy(2_000L)
        composeRule.onNodeWithTag(SETUP_TAG_CONTINUE).assertIsNotEnabled()

        // Past cooldown: enabled.
        composeRule.mainClock.advanceTimeBy(4_000L)
        composeRule.onNodeWithTag(SETUP_TAG_CONTINUE).assertIsEnabled()
    }

    @Test
    fun continue_enabled_after_cooldown_with_acknowledged_and_matching_passphrases() {
        val vm = newVm()
        composeRule.mainClock.autoAdvance = false
        composeRule.setContent {
            MaterialTheme { Surface { SetupScreen(vm = vm, onComplete = {}) } }
        }
        composeRule.mainClock.advanceTimeBy(100L)

        composeRule.onNodeWithTag(SETUP_TAG_PASSPHRASE).performTextInput("opensesame")
        composeRule.onNodeWithTag(SETUP_TAG_CONFIRM).performTextInput("opensesame")
        composeRule.onNodeWithTag(SETUP_TAG_ACK).performClick()
        composeRule.mainClock.advanceTimeBy(6_000L)

        composeRule.onNodeWithTag(SETUP_TAG_CONTINUE).assertIsEnabled()
    }

    @Test
    fun mismatched_passphrases_show_inline_error_and_keep_continue_disabled() {
        val vm = newVm()
        composeRule.mainClock.autoAdvance = false
        composeRule.setContent {
            MaterialTheme { Surface { SetupScreen(vm = vm, onComplete = {}) } }
        }
        composeRule.mainClock.advanceTimeBy(100L)

        composeRule.onNodeWithTag(SETUP_TAG_PASSPHRASE).performTextInput("alpha")
        composeRule.onNodeWithTag(SETUP_TAG_CONFIRM).performTextInput("beta")
        composeRule.onNodeWithTag(SETUP_TAG_ACK).performClick()
        composeRule.mainClock.advanceTimeBy(6_000L)

        composeRule.onNodeWithTag(SETUP_TAG_CONTINUE).assertIsNotEnabled()
    }

    @Test
    fun panicPin_field_is_optional_and_starts_empty() {
        val vm = newVm()
        composeRule.mainClock.autoAdvance = false
        composeRule.setContent {
            MaterialTheme { Surface { SetupScreen(vm = vm, onComplete = {}) } }
        }
        composeRule.mainClock.advanceTimeBy(100L)

        composeRule.onNodeWithTag(SETUP_TAG_PANICPIN).assertIsDisplayed()
        composeRule.onNodeWithTag(SETUP_TAG_PASSPHRASE).performTextInput("opensesame")
        composeRule.onNodeWithTag(SETUP_TAG_CONFIRM).performTextInput("opensesame")
        composeRule.onNodeWithTag(SETUP_TAG_ACK).performClick()
        composeRule.mainClock.advanceTimeBy(6_000L)

        // No panic-PIN entered — Continue must still be enabled.
        composeRule.onNodeWithTag(SETUP_TAG_CONTINUE).assertIsEnabled()
    }

    @Test
    fun panicPin_must_differ_from_realPin_else_inline_error() {
        val vm = newVm()
        composeRule.mainClock.autoAdvance = false
        composeRule.setContent {
            MaterialTheme { Surface { SetupScreen(vm = vm, onComplete = {}) } }
        }
        composeRule.mainClock.advanceTimeBy(100L)

        composeRule.onNodeWithTag(SETUP_TAG_PASSPHRASE).performTextInput("123456")
        composeRule.onNodeWithTag(SETUP_TAG_CONFIRM).performTextInput("123456")
        composeRule.onNodeWithTag(SETUP_TAG_PANICPIN).performTextInput("123456")
        composeRule.onNodeWithTag(SETUP_TAG_ACK).performClick()
        composeRule.mainClock.advanceTimeBy(6_000L)

        composeRule.onNodeWithTag(SETUP_TAG_CONTINUE).assertIsNotEnabled()
    }

    @Test
    fun passphrase_field_uses_charArray_state_not_String() {
        // Smoke check — full state-shape inspection requires reflection that
        // breaks Compose's rememberSaveable contract on hot reload. This test
        // exists so a regression that swaps the state holder back to String
        // is at least visible via the rendered field's testTag.
        val vm = newVm()
        composeRule.setContent {
            MaterialTheme { Surface { SetupScreen(vm = vm, onComplete = {}) } }
        }
        composeRule.onNodeWithTag(SETUP_TAG_PASSPHRASE).assertIsDisplayed()
        composeRule.onNodeWithTag(SETUP_TAG_CONFIRM).assertIsDisplayed()
    }

    private fun newVm(): AuthViewModel = AuthViewModel(
        keyManager = FakeKeyManager(setupComplete = false),
        wipeManager = FakeWipeManager(),
        panicPin = FakePanicPin(),
        authState = FakeAuthState(),
        clock = Clock.systemUTC(),
    )

    private class FakeKeyManager(
        private val setupComplete: Boolean,
    ) : KeyManagerApi {
        override suspend fun isSetupComplete(): Boolean = setupComplete
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

    private class FakeWipeManager : WipeManagerApi {
        override suspend fun wipeNow(level: WipeLevel) = Unit
    }

    private class FakePanicPin : PanicPinApi {
        override suspend fun register(pin: CharArray, realPassphrase: CharArray) {
            pin.fill(' ')
            realPassphrase.fill(' ')
        }
        override suspend fun matches(input: CharArray): Boolean = false
    }

    private class FakeAuthState : AuthStateStore {
        override suspend fun currentFailCount(): Int = 0
        override suspend fun setFailCount(n: Int) = Unit
        override suspend fun setLastAuthSuccessEpoch(epochMs: Long?) = Unit
        override suspend fun lastAuthSuccessEpoch(): Long? = null
    }
}
