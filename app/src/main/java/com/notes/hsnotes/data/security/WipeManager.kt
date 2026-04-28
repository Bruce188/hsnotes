package com.notes.hsnotes.data.security

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Wipe-ladder implementation. Plan §7.1.
 *
 * The four [WipeLevel]s collapse into a small number of primitives:
 *
 *  | Level         | KeyManager.cryptoErase | onLock | onUiLock | App-data delete |
 *  |---------------|------------------------|--------|----------|-----------------|
 *  | LOCK          |                        | yes    | yes      |                 |
 *  | SOFT          | yes                    | yes    | yes      |                 |
 *  | CRYPTO_ERASE  | yes                    | yes    |          |                 |
 *  | NUCLEAR       | yes                    | yes    | yes      | yes             |
 *
 * `onLock` closes the open SQLCipher database (drops the in-memory DEK held
 * by SQLCipher), unbinds SecurePrefs (drops the in-memory Tink keyset
 * reference), and clears any other in-process key material. `onUiLock`
 * notifies the auth gate to flip back to [com.notes.hsnotes.ui.auth.LockState.Locked].
 *
 * The two callbacks are injected so tests can verify side effects without
 * requiring a full Application context — and so the production wiring can
 * thread the existing `App.closeAndZeroizeDatabase` / lock-signal emit
 * machinery without WipeManager taking a dependency on the App class.
 *
 * `BLKDISCARD`: Android does not expose a public discard API. After unlinking
 * the file the kernel schedules trim asynchronously on supported devices.
 * `StorageManager.allocateBytes` is a hint for *future* allocation, not for
 * destruction — calling it here would be incorrect. We document the gap and
 * rely on filesystem-level trim semantics post-unlink.
 */
class WipeManager(
    private val context: Context,
    private val keyManager: KeyManagerApi,
    private val onLock: suspend () -> Unit = {},
    private val onUiLock: suspend () -> Unit = {},
) : WipeManagerApi {

    override suspend fun wipeNow(level: WipeLevel) {
        when (level) {
            WipeLevel.LOCK -> {
                onLock()
                onUiLock()
            }
            WipeLevel.SOFT -> {
                keyManager.cryptoErase()
                onLock()
                onUiLock()
            }
            WipeLevel.CRYPTO_ERASE -> {
                keyManager.cryptoErase()
                onLock()
            }
            WipeLevel.NUCLEAR -> {
                keyManager.cryptoErase()
                onLock()
                deleteAppDataFiles()
                onUiLock()
            }
        }
    }

    private suspend fun deleteAppDataFiles() = withContext(Dispatchers.IO) {
        // Room database files (DB + WAL + SHM).
        for (name in listOf("notes.db", "notes.db-wal", "notes.db-shm")) {
            runCatching { context.getDatabasePath(name).delete() }
        }
        // DataStore directory ("settings" pref store + any others).
        runCatching {
            File(context.filesDir, "datastore").deleteRecursively()
        }
        // SecurePrefs file (Tink keyset + ciphertext blobs).
        runCatching { File(context.filesDir, "secure_prefs.bin").delete() }
        runCatching { File(context.filesDir, "secure_prefs.json").delete() }
        // sec/ directory: salt.bin, wrapped_dek.bin, attested_ts.bin (KeyManager.cryptoErase
        // already overwrites the wrapped DEK + salt; the unlink is belt-and-braces).
        runCatching {
            File(context.filesDir, CryptoConfig.SEC_DIR_NAME).deleteRecursively()
        }
        // Exports / shared / cache.
        runCatching { File(context.filesDir, "exports").deleteRecursively() }
        runCatching { context.cacheDir.deleteRecursively() }
        runCatching { context.codeCacheDir.deleteRecursively() }
        // External app-private dir if mounted (do NOT touch shared external storage).
        runCatching {
            context.getExternalFilesDir(null)?.deleteRecursively()
        }
    }

}
