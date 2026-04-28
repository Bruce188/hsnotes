package com.notes.hsnotes.ui.screens.edit

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.notes.hsnotes.App
import com.notes.hsnotes.R

const val NOTE_EDIT_TAG_TITLE: String = "note_edit_title"
const val NOTE_EDIT_TAG_BODY: String = "note_edit_body"
const val NOTE_EDIT_TAG_TAG: String = "note_edit_tag"
const val NOTE_EDIT_TAG_SAVE: String = "note_edit_save"
const val NOTE_EDIT_TAG_DELETE: String = "note_edit_delete"
const val NOTE_EDIT_TAG_BACK: String = "note_edit_back"

/**
 * Note editor. Two text fields (title, body) plus an optional tag row.
 *
 * - "Back" saves on its way out (no explicit "discard" affordance: leaving
 *   with an empty title+body discards a fresh note; otherwise we save).
 * - "Delete" surfaces an AlertDialog (irreversible, no soft-delete).
 *
 * The note is hydrated by [NoteEditViewModel.init]; until then the fields
 * are empty placeholders. We intentionally do NOT block render on `loaded`
 * — the user can start typing into a "new note" frame without a flash, and
 * the edit-existing case lands fast enough on encrypted SQLite that a
 * 100ms-class shimmer is not worth it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NoteEditScreen(
    noteId: Long?,
    onDone: () -> Unit,
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val vm: NoteEditViewModel = viewModel(factory = NoteEditViewModel.factory(app, noteId))
    val state by vm.state.collectAsState()
    val keyboard = LocalSoftwareKeyboardController.current

    var showDeleteDialog by remember { mutableStateOf(false) }

    // Row removed from under us (concurrent delete) — bail.
    LaunchedEffect(state.missing) {
        if (state.missing) onDone()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = if (state.isNew) {
                            stringResource(R.string.edit_title_new)
                        } else {
                            stringResource(R.string.edit_title_edit)
                        }
                    )
                },
                navigationIcon = {
                    IconButton(
                        onClick = {
                            keyboard?.hide()
                            vm.save(onDone)
                        },
                        modifier = Modifier.testTag(NOTE_EDIT_TAG_BACK),
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.common_back),
                        )
                    }
                },
                actions = {
                    if (!state.isNew) {
                        IconButton(
                            onClick = { showDeleteDialog = true },
                            modifier = Modifier.testTag(NOTE_EDIT_TAG_DELETE),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Delete,
                                contentDescription = stringResource(R.string.common_delete),
                            )
                        }
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = state.title,
                onValueChange = vm::setTitle,
                label = { Text(stringResource(R.string.edit_title_label)) },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(NOTE_EDIT_TAG_TITLE),
            )
            OutlinedTextField(
                value = state.body,
                onValueChange = vm::setBody,
                label = { Text(stringResource(R.string.edit_body_label)) },
                minLines = 6,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(NOTE_EDIT_TAG_BODY),
            )
            OutlinedTextField(
                value = state.tag,
                onValueChange = vm::setTag,
                label = { Text(stringResource(R.string.edit_tag_label)) },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(NOTE_EDIT_TAG_TAG),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.edit_save),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.outline,
                modifier = Modifier.testTag(NOTE_EDIT_TAG_SAVE),
            )
        }
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text(stringResource(R.string.edit_dlg_delete_title)) },
            text = { Text(stringResource(R.string.edit_dlg_delete_text)) },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteDialog = false
                    vm.delete(onDone)
                }) {
                    Text(stringResource(R.string.common_delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text(stringResource(R.string.common_cancel))
                }
            },
        )
    }
}
