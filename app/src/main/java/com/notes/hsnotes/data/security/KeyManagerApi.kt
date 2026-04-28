package com.notes.hsnotes.data.security

/**
 * Minimal contract for the unlock pipeline. Extracted so [com.notes.hsnotes.ui.auth.AuthViewModel]
 * (and its tests) can depend on a fakeable surface without dragging the
 * Android Keystore JNI into JVM unit tests.
 *
 * Plan §5.1 — "Tests use a fake KeyManager interface (extract `interface
 * KeyManagerApi` + `class KeyManager : KeyManagerApi` if you must)."
 */
interface KeyManagerApi {
    suspend fun isSetupComplete(): Boolean
    suspend fun setupNew(passphrase: CharArray)
    suspend fun unlock(passphrase: CharArray): Result<Dek>
    suspend fun changePassphrase(oldPassphrase: CharArray, newPassphrase: CharArray)
    suspend fun cryptoErase()
}
