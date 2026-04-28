package com.notes.hsnotes.ui.migration

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.notes.hsnotes.R
import com.notes.hsnotes.ui.auth.LockState

/**
 * Test tags exposed for instrumentation. Plan §8.1 connectedDebugAndroidTest
 * reaches into them once a device is available.
 */
const val MIGRATION_TAG_PROGRESS: String = "migration_progress"
const val MIGRATION_TAG_ERROR: String = "migration_error"
const val MIGRATION_TAG_RETRY: String = "migration_retry"

/**
 * Plan §8.1 — first-run upgrade wizard for users coming from a pre-retrofit
 * plaintext database. Driven entirely by [LockState.Migrating]:
 *
 *  - `error == null` → progress bar with `"current / total"` rows label.
 *    `total == 0` (no row count yet) renders an indeterminate spinner.
 *  - `error != null` → red recovery card with a "Back to login" button that
 *    invokes [onDismissError]. The plaintext database is intact at this point
 *    (the migration only mutates it after every verify step lands), so the
 *    user can re-authenticate and the next unlock retries the migration.
 */
@Composable
fun MigrationWizardScreen(
    state: LockState.Migrating,
    onDismissError: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.migration_title),
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.migration_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(24.dp))

        if (state.error != null) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(MIGRATION_TAG_ERROR),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                ),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = stringResource(R.string.migration_error_title),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = stringResource(R.string.migration_error_recovery),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = onDismissError,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(MIGRATION_TAG_RETRY),
            ) {
                Text(stringResource(R.string.migration_back_to_login))
            }
        } else {
            if (state.total > 0) {
                LinearProgressIndicator(
                    progress = {
                        if (state.total <= 0) 0f
                        else (state.current.toFloat() / state.total.toFloat())
                            .coerceIn(0f, 1f)
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(MIGRATION_TAG_PROGRESS),
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(
                        R.string.migration_progress,
                        state.current,
                        state.total,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                CircularProgressIndicator(
                    modifier = Modifier.testTag(MIGRATION_TAG_PROGRESS),
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.migration_progress_starting),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
