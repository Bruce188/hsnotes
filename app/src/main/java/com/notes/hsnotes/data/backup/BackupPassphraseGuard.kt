package com.notes.hsnotes.data.backup

/**
 * Plan § Encrypted Backup. Enforces "backup passphrase MUST differ from the
 * unlock passphrase" — leakage isolation.
 *
 * Implementations consult the live [com.notes.hsnotes.data.security.KeyManager]
 * and return `true` iff [candidate] would unlock the live wrapped DEK. The
 * ViewModel layer must call this BEFORE invoking [EncryptedBackupCodec.encode]
 * so that an exact-match passphrase is rejected without producing a backup
 * file.
 *
 * Implementations MUST wipe any DEK they recover during the check; the guard
 * surface returns only a Boolean so the ViewModel never sees raw key material.
 */
fun interface BackupPassphraseGuard {
    /**
     * @return `true` if [candidate] equals the current unlock passphrase
     *         (i.e. would successfully unlock the wrapped DEK).
     *         The guard does NOT wipe [candidate]; the caller still owns it.
     */
    suspend fun isSameAsUnlockPassphrase(candidate: CharArray): Boolean
}

/**
 * Thrown by `SettingsViewModel.exportEncrypted` (and the equivalent
 * import path) when the backup passphrase coincides with the unlock
 * passphrase — defense against single-passphrase compromise propagating
 * to off-device backups.
 */
class BackupPassphraseEqualsUnlock : Exception("Backup passphrase must differ from the unlock passphrase")
