package com.notes.hsnotes.ui.auth

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.notes.hsnotes.R
import com.notes.hsnotes.data.security.CryptoConfig
import kotlinx.coroutines.delay

/**
 * Test tags for [AuthGateScreen]. Plan §5.3 androidTest cases use them to
 * drive the screen without depending on locale-specific copy.
 */
const val AUTH_GATE_TAG_PASSPHRASE: String = "auth_gate_passphrase"
const val AUTH_GATE_TAG_SUBMIT: String = "auth_gate_submit"
const val AUTH_GATE_TAG_ATTEMPT_COUNTER: String = "auth_gate_attempt_counter"
const val AUTH_GATE_TAG_WARNING: String = "auth_gate_warning"
const val AUTH_GATE_TAG_BACKOFF: String = "auth_gate_backoff"
const val AUTH_GATE_TAG_FAILED: String = "auth_gate_failed"

/**
 * Unlock prompt. Plan §5.3.
 *
 * Renders the attempt counter "X / [CryptoConfig.WIPE_FAIL_THRESHOLD]" so the
 * user knows how many attempts remain before crypto-erase. At
 * failCount ∈ {3, 4} an extra warning banner surfaces — by attempt 5 the
 * ViewModel has already issued the wipe and we transition to [LockState.Wiped].
 *
 * Failure messaging is generic ("Incorrect — try again") regardless of
 * underlying error class so the screen does not leak an oracle distinguishing
 * "no setup" vs "wrong passphrase" vs "Keystore corruption".
 *
 * During backoff the input + submit are disabled and a 1-Hz countdown ticker
 * displays remaining seconds. When backoff hits zero the field re-enables.
 *
 * After a failed attempt the local CharArray is wiped and the field clears so
 * the user starts each retry from a fresh buffer.
 */
@Composable
fun AuthGateScreen(vm: AuthViewModel) {
    val state by vm.state.collectAsState()

    val passphrase = remember { mutableStateOf(charArrayOf()) }
    var lastFailCount by remember { mutableIntStateOf(0) }
    var prevFailCount by remember { mutableIntStateOf(0) }
    var backoffRemaining by remember { mutableIntStateOf(0) }
    var failureBannerVisible by remember { mutableStateOf(false) }

    // Track failCount + drive the backoff ticker.
    LaunchedEffect(state) {
        val s = state
        if (s is LockState.Locked) {
            lastFailCount = s.failCount
            if (s.backoffSeconds > 0) {
                backoffRemaining = s.backoffSeconds
                while (backoffRemaining > 0) {
                    delay(1_000L)
                    backoffRemaining -= 1
                }
            } else {
                backoffRemaining = 0
            }
        }
    }

    // On a fresh failure: wipe the field + show the generic banner.
    LaunchedEffect(state) {
        val s = state
        if (s is LockState.Locked && s.failCount > prevFailCount) {
            passphrase.value.fill(' ')
            passphrase.value = charArrayOf()
            failureBannerVisible = true
        }
        if (s is LockState.Locked) prevFailCount = s.failCount
        if (s is LockState.Unlocked || s is LockState.Wiped) failureBannerVisible = false
    }

    DisposableEffect(Unit) {
        onDispose {
            passphrase.value.fill(' ')
        }
    }

    // Review V-N1 — PanicSpinner renders identical to Unlocking from a
    // coercer's POV but the underlying state machine never reached a real DEK.
    val isUnlocking = state is LockState.Unlocking || state is LockState.PanicSpinner
    val inputEnabled = !isUnlocking && backoffRemaining == 0
    val submitEnabled = inputEnabled && passphrase.value.isNotEmpty()

    val warningRemaining = CryptoConfig.WIPE_FAIL_THRESHOLD - lastFailCount
    val showWarning = lastFailCount in 3..(CryptoConfig.WIPE_FAIL_THRESHOLD - 1)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.security_gate_title),
            style = MaterialTheme.typography.headlineSmall,
        )

        Text(
            text = stringResource(
                R.string.security_gate_attempt_counter,
                lastFailCount + 1,
                CryptoConfig.WIPE_FAIL_THRESHOLD,
            ),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.testTag(AUTH_GATE_TAG_ATTEMPT_COUNTER),
        )

        if (showWarning) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(AUTH_GATE_TAG_WARNING),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                ),
            ) {
                Text(
                    text = stringResource(
                        R.string.security_gate_warning_n_remaining,
                        warningRemaining,
                    ),
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }

        OutlinedTextField(
            value = passphrase.value.concatToString(),
            onValueChange = { s ->
                passphrase.value.fill(' ')
                passphrase.value = s.toCharArray()
            },
            label = { Text(stringResource(R.string.security_gate_passphrase_label)) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = ImeAction.Done,
            ),
            singleLine = true,
            enabled = inputEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(AUTH_GATE_TAG_PASSPHRASE),
        )

        if (backoffRemaining > 0) {
            Text(
                text = stringResource(R.string.security_gate_backoff_seconds, backoffRemaining),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(AUTH_GATE_TAG_BACKOFF),
            )
        } else if (failureBannerVisible) {
            Text(
                text = stringResource(R.string.security_gate_failed),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag(AUTH_GATE_TAG_FAILED),
            )
        }

        Spacer(Modifier.height(8.dp))

        Button(
            onClick = {
                val copy = passphrase.value.copyOf()
                vm.unlock(copy)
            },
            enabled = submitEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(AUTH_GATE_TAG_SUBMIT),
        ) {
            Text(stringResource(R.string.security_gate_unlock))
        }
    }
}
