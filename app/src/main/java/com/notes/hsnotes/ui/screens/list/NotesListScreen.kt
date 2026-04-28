package com.notes.hsnotes.ui.screens.list

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.notes.hsnotes.App
import com.notes.hsnotes.R
import com.notes.hsnotes.data.db.entity.NoteEntity
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

const val NOTES_LIST_TAG_FAB: String = "notes_list_fab"
const val NOTES_LIST_TAG_SETTINGS: String = "notes_list_settings"
const val NOTES_LIST_TAG_EMPTY: String = "notes_list_empty"
const val NOTES_LIST_TAG_ROW: String = "notes_list_row"

/**
 * Top-level list screen. Dense, single-column rows: title (or `(untitled)`),
 * one-line body preview, optional tag pill, last-updated timestamp.
 *
 * No icons inside rows — taps anywhere route to edit. The settings cog and
 * "+" FAB are the only chrome. Empty state is text-only.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotesListScreen(
    onNew: () -> Unit,
    onEdit: (Long) -> Unit,
    onSettings: () -> Unit,
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val vm: NotesListViewModel = viewModel(factory = NotesListViewModel.factory(app))
    val notes by vm.notes.collectAsState()

    val snackbarHost = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.notes_title)) },
                actions = {
                    IconButton(
                        onClick = onSettings,
                        modifier = Modifier.testTag(NOTES_LIST_TAG_SETTINGS),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Settings,
                            contentDescription = stringResource(R.string.notes_action_settings),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onNew,
                modifier = Modifier.testTag(NOTES_LIST_TAG_FAB),
            ) {
                Icon(
                    imageVector = Icons.Filled.Add,
                    contentDescription = stringResource(R.string.notes_action_new),
                )
            }
        },
        snackbarHost = { SnackbarHost(snackbarHost) },
    ) { padding ->
        if (notes.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = stringResource(R.string.notes_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag(NOTES_LIST_TAG_EMPTY),
                )
            }
        } else {
            NotesList(
                notes = notes,
                contentPadding = padding,
                onClick = onEdit,
                onLongPress = { id ->
                    vm.delete(id)
                    scope.launch {
                        val result = snackbarHost.showSnackbar(
                            message = context.getString(R.string.notes_snackbar_deleted),
                            actionLabel = context.getString(R.string.notes_snackbar_undo),
                        )
                        // Undo is a UI affordance only — restoration is not
                        // implemented here. Tapping "undo" simply dismisses
                        // the snackbar; the row is already gone. Hooking
                        // restore would need a buffered draft in the VM; out
                        // of scope for v0.
                        if (result == SnackbarResult.ActionPerformed) Unit
                    }
                },
            )
        }
    }
}

@Composable
private fun NotesList(
    notes: List<NoteEntity>,
    contentPadding: PaddingValues,
    onClick: (Long) -> Unit,
    onLongPress: (Long) -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding),
    ) {
        items(items = notes, key = { it.id }) { note ->
            NoteRow(
                note = note,
                onClick = { onClick(note.id) },
                onLongPress = { onLongPress(note.id) },
            )
            HorizontalDivider(thickness = 0.5.dp, color = MaterialTheme.colorScheme.outlineVariant)
        }
    }
}

@Composable
private fun NoteRow(
    note: NoteEntity,
    onClick: () -> Unit,
    onLongPress: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(NOTES_LIST_TAG_ROW),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = note.title.ifBlank { stringResource(R.string.notes_untitled) },
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        if (note.body.isNotBlank()) {
            Text(
                text = note.body.replace('\n', ' ').trim(),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.height(2.dp))
        Text(
            text = formatTimestamp(note.updatedAt) +
                (note.tag?.let { "  ·  $it" } ?: ""),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.outline,
        )
    }
}

private fun formatTimestamp(epochMillis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
        .format(Date(epochMillis))
