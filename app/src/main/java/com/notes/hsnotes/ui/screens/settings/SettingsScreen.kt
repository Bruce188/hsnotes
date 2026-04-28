package com.notes.hsnotes.ui.screens.settings

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.notes.hsnotes.R
import com.notes.hsnotes.data.security.wipe
import java.time.LocalDate

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    vm: SettingsViewModel = viewModel()
) {
    val state by vm.state.collectAsState()
    val event by vm.events.collectAsState()
    val ctx = LocalContext.current
    val snackbar = remember { SnackbarHostState() }

    var pendingExportUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var pendingImportUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var pendingImportPassphrase by remember { mutableStateOf<CharArray?>(null) }
    var wipeStage by remember { mutableStateOf(0) } // 0 = closed, 1 = first confirm, 2 = second confirm

    val createDoc = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        if (uri != null) pendingExportUri = uri
    }
    val openDoc = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) pendingImportUri = uri
    }

    LaunchedEffect(event) {
        event?.let {
            val msg = when (it) {
                is SettingsViewModel.IoResult.Success -> it.message
                is SettingsViewModel.IoResult.Failure -> it.message
            }
            snackbar.showSnackbar(msg)
            vm.consumeEvent()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.common_back))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            SectionTitle(stringResource(R.string.settings_section_language))
            LanguageDropdown(
                selected = state.language,
                onSelect = vm::setLanguage
            )
            Spacer(Modifier.height(16.dp))

            SectionTitle(stringResource(R.string.settings_section_lock))
            LockTimeoutDropdown(
                selectedMs = state.lockTimeoutMs,
                onSelect = vm::setLockTimeoutMs,
            )
            Spacer(Modifier.height(16.dp))

            SectionTitle(stringResource(R.string.settings_section_backup))
            Text(
                stringResource(R.string.settings_backup_passphrase_warning),
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { createDoc.launch("hsnotes-backup-${LocalDate.now()}.hsbk") },
                    modifier = Modifier.weight(1f)
                ) { Text(stringResource(R.string.settings_backup_export)) }
                OutlinedButton(
                    onClick = { openDoc.launch(arrayOf("application/octet-stream", "*/*")) },
                    modifier = Modifier.weight(1f)
                ) { Text(stringResource(R.string.settings_backup_import)) }
            }
            Spacer(Modifier.height(24.dp))

            // Plan §7.1 — manual NUCLEAR wipe with double-confirm UX.
            SectionTitle(stringResource(R.string.settings_section_destructive))
            Button(
                onClick = { wipeStage = 1 },
                colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError,
                ),
                modifier = Modifier.fillMaxWidth()
            ) { Text(stringResource(R.string.settings_wipe_button)) }
            Spacer(Modifier.height(24.dp))

            Text(
                stringResource(R.string.settings_version),
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(Modifier.height(24.dp))
        }
    }

    if (wipeStage == 1) {
        AlertDialog(
            onDismissRequest = { wipeStage = 0 },
            title = { Text(stringResource(R.string.settings_wipe_confirm_1_title)) },
            text = { Text(stringResource(R.string.settings_wipe_confirm_1_text)) },
            confirmButton = {
                TextButton(onClick = { wipeStage = 2 }) {
                    Text(stringResource(R.string.settings_wipe_confirm_1_continue))
                }
            },
            dismissButton = {
                TextButton(onClick = { wipeStage = 0 }) {
                    Text(stringResource(R.string.common_cancel))
                }
            }
        )
    }
    if (wipeStage == 2) {
        AlertDialog(
            onDismissRequest = { wipeStage = 0 },
            title = { Text(stringResource(R.string.settings_wipe_confirm_2_title)) },
            text = { Text(stringResource(R.string.settings_wipe_confirm_2_text)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        wipeStage = 0
                        vm.requestWipe()
                    }
                ) {
                    Text(
                        stringResource(R.string.settings_wipe_confirm_2_action),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { wipeStage = 0 }) {
                    Text(stringResource(R.string.common_cancel))
                }
            }
        )
    }

    // Export — prompt for backup passphrase, then ship encrypted bytes.
    val exportUri = pendingExportUri
    if (exportUri != null) {
        BackupPassphraseDialog(
            title = stringResource(R.string.settings_backup_passphrase_export_title),
            confirmLabel = stringResource(R.string.settings_backup_export),
            onDismiss = { pendingExportUri = null },
            onConfirm = { passphrase ->
                vm.exportEncrypted(ctx, exportUri, passphrase)
                pendingExportUri = null
            },
        )
    }

    // Import — first ask for the passphrase, THEN show merge/replace.
    val importUri = pendingImportUri
    if (importUri != null && pendingImportPassphrase == null) {
        BackupPassphraseDialog(
            title = stringResource(R.string.settings_backup_passphrase_import_title),
            confirmLabel = stringResource(R.string.common_ok),
            onDismiss = { pendingImportUri = null },
            onConfirm = { passphrase ->
                pendingImportPassphrase = passphrase
            },
        )
    }
    val importPass = pendingImportPassphrase
    if (importUri != null && importPass != null) {
        AlertDialog(
            onDismissRequest = {
                importPass.wipe()
                pendingImportPassphrase = null
                pendingImportUri = null
            },
            title = { Text(stringResource(R.string.settings_dlg_import_title)) },
            text = { Text(stringResource(R.string.settings_dlg_import_text)) },
            confirmButton = {
                TextButton(onClick = {
                    vm.importEncrypted(ctx, importUri, importPass, replace = false)
                    pendingImportPassphrase = null
                    pendingImportUri = null
                }) { Text(stringResource(R.string.settings_dlg_import_merge)) }
            },
            dismissButton = {
                TextButton(onClick = {
                    vm.importEncrypted(ctx, importUri, importPass, replace = true)
                    pendingImportPassphrase = null
                    pendingImportUri = null
                }) { Text(stringResource(R.string.settings_dlg_import_replace)) }
            }
        )
    }
}

/**
 * Review B4 — backup passphrase entry uses a CharArray-backed app-side state,
 * matching SetupScreen's contract. Compose's stock [OutlinedTextField] bridges
 * through [String] internally so a leak window of one keystroke is unavoidable
 * without a custom TextField; this is the same trade-off documented in
 * SetupScreen. The app-side buffer is wiped on every keystroke, on dismiss,
 * and on dispose.
 */
@Composable
private fun BackupPassphraseDialog(
    title: String,
    confirmLabel: String,
    onDismiss: () -> Unit,
    onConfirm: (CharArray) -> Unit,
) {
    var buffer by remember { mutableStateOf(charArrayOf()) }
    DisposableEffect(Unit) {
        onDispose { buffer.wipe() }
    }
    fun replaceBuffer(next: CharArray) {
        val prior = buffer
        buffer = next
        prior.wipe()
    }
    AlertDialog(
        onDismissRequest = {
            replaceBuffer(charArrayOf())
            onDismiss()
        },
        title = { Text(title) },
        text = {
            Column {
                Text(
                    stringResource(R.string.settings_backup_passphrase_warning),
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    // Bridges through String inside Compose — unavoidable.
                    value = String(buffer),
                    onValueChange = { newText -> replaceBuffer(newText.toCharArray()) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    label = { Text(stringResource(R.string.settings_backup_passphrase_label)) },
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (buffer.isNotEmpty()) {
                    // Hand ownership to onConfirm; replace buffer with a fresh
                    // empty array (does NOT wipe the handed-off copy).
                    val handOff = buffer
                    buffer = charArrayOf()
                    onConfirm(handOff)
                }
            }) { Text(confirmLabel) }
        },
        dismissButton = {
            TextButton(onClick = {
                replaceBuffer(charArrayOf())
                onDismiss()
            }) { Text(stringResource(R.string.common_cancel)) }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LanguageDropdown(
    selected: String,
    onSelect: (String) -> Unit
) {
    val englishLabel = stringResource(R.string.settings_lang_english)
    val frenchLabel = stringResource(R.string.settings_lang_french)
    val dutchLabel = stringResource(R.string.settings_lang_dutch)
    val options = listOf(
        "en" to englishLabel,
        "fr" to frenchLabel,
        "nl" to dutchLabel
    )
    var expanded by remember { mutableStateOf(false) }
    val display = options.firstOrNull { it.first == selected }?.second ?: englishLabel
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        OutlinedTextField(
            value = display,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.settings_language_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth()
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            options.forEach { (key, label) ->
                DropdownMenuItem(
                    text = { Text(label) },
                    onClick = { onSelect(key); expanded = false }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LockTimeoutDropdown(
    selectedMs: Long,
    onSelect: (Long) -> Unit,
) {
    val options = listOf(
        30_000L to stringResource(R.string.settings_lock_timeout_30s),
        120_000L to stringResource(R.string.settings_lock_timeout_2m),
        300_000L to stringResource(R.string.settings_lock_timeout_5m),
        900_000L to stringResource(R.string.settings_lock_timeout_15m),
    )
    var expanded by remember { mutableStateOf(false) }
    val display = options.firstOrNull { it.first == selectedMs }?.second
        ?: options.first().second
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        OutlinedTextField(
            value = display,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.settings_lock_timeout_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth()
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            options.forEach { (ms, label) ->
                DropdownMenuItem(
                    text = { Text(label) },
                    onClick = { onSelect(ms); expanded = false }
                )
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(6.dp))
}
