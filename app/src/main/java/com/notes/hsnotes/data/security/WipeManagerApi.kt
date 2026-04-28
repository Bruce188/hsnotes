package com.notes.hsnotes.data.security

/**
 * Severity ladder for [WipeManagerApi.wipeNow]. Plan §7.1.
 *
 *  - [LOCK]         — zeroize in-memory state only (close the encrypted DB,
 *                     drop the DEK reference, signal the UI to lock). No disk
 *                     mutation. Used by the LifecycleLock idle timeout.
 *  - [SOFT]         — [CRYPTO_ERASE] plus locking the UI back to Locked.
 *                     Used when an automated trigger (panic PIN, dead-man,
 *                     fail-threshold) wants the user back at the auth gate
 *                     after the cryptographic destruction completes.
 *  - [CRYPTO_ERASE] — destroy KEK + wrapped DEK file + Keystore alias.
 *                     Encrypted blobs (Room DB, SecurePrefs keyset, attested
 *                     timestamp) become permanently unreadable. Fast.
 *  - [NUCLEAR]      — [CRYPTO_ERASE] plus best-effort deletion of every
 *                     app-data file: Room DB + WAL + SHM, DataStore directory,
 *                     SecurePrefs file, exports, cache. The `BLKDISCARD` hint
 *                     is best-effort — the OS schedules trim post-unlink, no
 *                     public API exposes it directly.
 */
enum class WipeLevel { LOCK, SOFT, CRYPTO_ERASE, NUCLEAR }

/**
 * Contract for the destructive-erase pipeline. The full implementation lands
 * in Phase 7.1; the interface lives here so [com.notes.hsnotes.ui.auth.AuthViewModel]
 * can take it as a dependency under test without pulling in real file IO.
 */
interface WipeManagerApi {
    /**
     * Synchronously (from the caller's coroutine perspective) tear down all
     * key material at the requested level. Idempotent — safe to call twice.
     */
    suspend fun wipeNow(level: WipeLevel)
}
