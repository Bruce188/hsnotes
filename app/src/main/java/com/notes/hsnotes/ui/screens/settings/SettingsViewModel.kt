package com.notes.hsnotes.ui.screens.settings

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.notes.hsnotes.App
import com.notes.hsnotes.data.backup.BackupPassphraseEqualsUnlock
import com.notes.hsnotes.data.backup.BackupPassphraseGuard
import com.notes.hsnotes.data.backup.BackupSerializer
import com.notes.hsnotes.data.backup.CorruptBackupPayload
import com.notes.hsnotes.data.backup.EncryptedBackupCodec
import com.notes.hsnotes.data.backup.WrongBackupPassphrase
import com.notes.hsnotes.data.security.KeyManager
import com.notes.hsnotes.data.security.WipeLevel
import com.notes.hsnotes.data.security.WipeManager
import com.notes.hsnotes.data.security.wipe
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SettingsViewModel(app: Application) : AndroidViewModel(app) {

    private val appRef = app as App
    private val repo = appRef.repository
    private val settings = appRef.settings
    // Review B1 — KeyManager MUST use the same calibrated Argon2 params as
    // AuthViewModel.factory; otherwise [backupGuard.unlock] silently fails on
    // calibrated devices (wrapped DEK is keyed to calibrated m, not 256 MiB).
    //
    // Review P-2 — construction deferred to a viewModelScope.async on
    // [Dispatchers.Default]. The default Compose `viewModel()` factory builds
    // this on the Main thread; calling `awaitArgon2Params()` directly in the
    // property initializer would `runBlocking` on Main if the cold-start
    // calibrator hadn't yet resolved (rare but structurally live). All
    // consumers (`backupGuard`, `requestWipe`) `.await()` this Deferred from
    // their own coroutine — none of those paths run on Main.
    private val keyManagerDeferred: Deferred<KeyManager> =
        viewModelScope.async(Dispatchers.Default) {
            KeyManager(appRef, params = appRef.awaitArgon2Params())
        }
    private val wipeManagerDeferred: Deferred<WipeManager> =
        viewModelScope.async(Dispatchers.Default) {
            WipeManager(
                context = appRef,
                keyManager = keyManagerDeferred.await(),
                onLock = {
                    appRef.closeAndZeroizeDatabase()
                    appRef.settings.unbindSecurePrefs()
                },
                onUiLock = { appRef.emitLockSignal() },
            )
        }

    private val backupCodec: EncryptedBackupCodec = EncryptedBackupCodec()

    /**
     * Default guard runs the candidate through [KeyManager.unlock]. Tests
     * inject a stub. The candidate is wiped by [KeyManager.unlock]; we pass
     * a copy and accept the wipe.
     */
    private val backupGuard: BackupPassphraseGuard = BackupPassphraseGuard { candidate ->
        val copy = candidate.copyOf()
        val km = keyManagerDeferred.await()
        val res = km.unlock(copy)
        res.fold(
            onSuccess = { dek ->
                dek.wipe()
                true
            },
            onFailure = { false },
        )
    }

    sealed interface IoResult {
        data class Success(val message: String) : IoResult
        data class Failure(val message: String) : IoResult
    }

    data class UiState(
        val language: String = "en",
        val lockTimeoutMs: Long = 60_000L,
    )

    val state: StateFlow<UiState> = settings.flow.map { s ->
        UiState(
            language = s.language ?: "en",
            lockTimeoutMs = s.lockTimeoutMs,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), UiState())

    private val _events = MutableStateFlow<IoResult?>(null)
    val events: StateFlow<IoResult?> = _events

    fun consumeEvent() { _events.value = null }

    fun setLanguage(tag: String) = viewModelScope.launch {
        settings.setLanguage(tag)
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))
    }

    fun setLockTimeoutMs(ms: Long) = viewModelScope.launch {
        settings.setLockTimeoutMs(ms)
    }

    fun exportTo(context: Context, uri: Uri) = viewModelScope.launch {
        try {
            val backup = repo.buildBackup()
            val text = BackupSerializer.encode(backup)
            withContext(Dispatchers.IO) {
                context.contentResolver.openOutputStream(uri)?.use { os ->
                    os.bufferedWriter().use { it.write(text) }
                } ?: error("Could not open output stream")
            }
            _events.value = IoResult.Success("Exported")
        } catch (t: Throwable) {
            _events.value = IoResult.Failure("Export failed: ${t.message}")
        }
    }

    /**
     * User-initiated NUCLEAR wipe. Plan §7.1 destructive button.
     *
     * Caller is responsible for the double-confirm UX (two AlertDialogs in
     * SettingsScreen). After the call:
     *  - All key material is destroyed (cryptoErase).
     *  - Room DB + DataStore + SecurePrefs + caches are unlinked.
     *  - In-process DEK is dropped, SecurePrefs is unbound.
     *  - lockSignal fires, the auth gate transitions back to Setup (no
     *    wrapped DEK exists, so the next render is SetupScreen).
     */
    fun requestWipe() = viewModelScope.launch {
        try {
            wipeManagerDeferred.await().wipeNow(WipeLevel.NUCLEAR)
            _events.value = IoResult.Success("Wiped")
        } catch (t: Throwable) {
            _events.value = IoResult.Failure("Wipe failed: ${t.message}")
        }
    }

    fun importFrom(context: Context, uri: Uri, replace: Boolean) = viewModelScope.launch {
        try {
            val text = withContext(Dispatchers.IO) {
                context.contentResolver.openInputStream(uri)?.use { it.bufferedReader().readText() }
            } ?: error("Could not open input stream")
            val backup = BackupSerializer.decode(text)
            applyBackup(backup, replace)
            _events.value = IoResult.Success(if (replace) "Restored (replaced)" else "Imported (merged)")
        } catch (t: Throwable) {
            _events.value = IoResult.Failure("Import failed: ${t.message}")
        }
    }

    private suspend fun applyBackup(
        backup: com.notes.hsnotes.data.backup.BackupV1,
        replace: Boolean,
    ) {
        if (replace) repo.replaceFromBackup(backup) else repo.mergeFromBackup(backup)
    }

    /**
     * Encrypted-backup export. Plan § Encrypted Backup.
     *
     *  1. Reject if [passphrase] equals the live unlock passphrase (guard).
     *  2. Build [com.notes.hsnotes.data.backup.BackupV1].
     *  3. Encode via [EncryptedBackupCodec] (Argon2id + AES-256-GCM, 4 KiB-padded).
     *  4. Stream bytes to [uri].
     *
     * [passphrase] is wiped before this method returns (codec wipes its copy;
     * we wipe the caller's array in a finally).
     */
    fun exportEncrypted(context: Context, uri: Uri, passphrase: CharArray) = viewModelScope.launch {
        val pass = passphrase
        try {
            if (backupGuard.isSameAsUnlockPassphrase(pass)) {
                throw BackupPassphraseEqualsUnlock()
            }
            val backup = repo.buildBackup()
            // Codec wipes its copy of the passphrase; pass a fresh copy so
            // we still control the original for the finally-wipe.
            val ciphertext = backupCodec.encode(backup, pass.copyOf())
            withContext(Dispatchers.IO) {
                context.contentResolver.openOutputStream(uri)?.use { os ->
                    os.write(ciphertext)
                    os.flush()
                } ?: error("Could not open output stream")
            }
            _events.value = IoResult.Success("Exported")
        } catch (e: BackupPassphraseEqualsUnlock) {
            _events.value = IoResult.Failure(e.message ?: "Backup passphrase invalid")
        } catch (t: Throwable) {
            _events.value = IoResult.Failure("Export failed: ${t.message}")
        } finally {
            pass.wipe()
        }
    }

    /**
     * Encrypted-backup import. Inverse of [exportEncrypted]. Generic failure
     * for wrong passphrase / corrupt header (no oracle); distinct failure
     * for an authenticated-but-malformed payload.
     */
    fun importEncrypted(
        context: Context,
        uri: Uri,
        passphrase: CharArray,
        replace: Boolean,
    ) = viewModelScope.launch {
        val pass = passphrase
        try {
            val bytes = withContext(Dispatchers.IO) {
                context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            } ?: error("Could not open input stream")
            val backup = backupCodec.decode(bytes, pass.copyOf())
            applyBackup(backup, replace)
            _events.value = IoResult.Success(if (replace) "Restored (replaced)" else "Imported (merged)")
        } catch (_: WrongBackupPassphrase) {
            _events.value = IoResult.Failure("Backup passphrase rejected")
        } catch (_: CorruptBackupPayload) {
            _events.value = IoResult.Failure("Backup file is corrupt")
        } catch (t: Throwable) {
            _events.value = IoResult.Failure("Import failed: ${t.message}")
        } finally {
            pass.wipe()
        }
    }
}
