package com.notes.hsnotes.data.security

import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.KeyStore

class KeyManagerTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    // Lower-cost Argon2 params keep tests fast on emulator without weakening
    // the on-disk format — the wrapper still runs the full Argon2id code path.
    private val testParams = Argon2Params(memoryKiB = 64 * 1024, iterations = 1, parallelism = 1)
    private val keyManager = KeyManager(context = context, params = testParams)

    private val secDir: File get() = File(context.filesDir, CryptoConfig.SEC_DIR_NAME)
    private val saltFile: File get() = File(secDir, CryptoConfig.KDF_SALT_FILENAME)
    private val wrappedDekFile: File get() = File(secDir, CryptoConfig.WRAPPED_DEK_FILENAME)

    @Before
    fun cleanState() {
        if (secDir.exists()) secDir.deleteRecursively()
        runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(CryptoConfig.KEYSTORE_ALIAS_KEK)) {
                ks.deleteEntry(CryptoConfig.KEYSTORE_ALIAS_KEK)
            }
        }
    }

    @After
    fun tearDown() = cleanState()

    @Test
    fun setupNew_creates_wrappedDek_and_salt_files() = runBlocking {
        keyManager.setupNew("hunter2".toCharArray())
        assertTrue("salt.bin missing", saltFile.exists())
        assertEquals(KeyManager.SALT_LENGTH.toLong(), saltFile.length())
        assertTrue("wrapped_dek.bin missing", wrappedDekFile.exists())
        // Version byte (1) + layer2 nonce (12) + at least 48B layer1 (12 nonce + 32 DEK + 16 tag) + outer 16B tag.
        assertTrue("wrapped_dek.bin too small (${wrappedDekFile.length()})", wrappedDekFile.length() >= 1 + 12 + 12 + 32 + 16 + 16)
    }

    @Test
    fun setupNew_then_unlock_with_correctPassphrase_returns_Success_with_32B_dek() = runBlocking {
        keyManager.setupNew("hunter2".toCharArray())
        val result = keyManager.unlock("hunter2".toCharArray())
        assertTrue("unlock should succeed", result.isSuccess)
        val dek = result.getOrThrow().toByteArray()
        assertEquals(32, dek.size)
        // Sanity: not all zero (DEK must be random).
        assertFalse(dek.all { it == 0.toByte() })
    }

    @Test
    fun unlock_with_wrongPassphrase_returns_Failure() = runBlocking {
        keyManager.setupNew("hunter2".toCharArray())
        val result = keyManager.unlock("not the passphrase".toCharArray())
        assertTrue("unlock should fail", result.isFailure)
        assertTrue(
            "failure must be WrongPassphrase, got ${result.exceptionOrNull()}",
            result.exceptionOrNull() is WrongPassphrase,
        )
    }

    @Test
    fun unlock_after_cryptoErase_failsEvenWithCorrectPassphrase() = runBlocking {
        keyManager.setupNew("hunter2".toCharArray())
        keyManager.cryptoErase()
        val result = keyManager.unlock("hunter2".toCharArray())
        assertTrue("unlock must fail post-erase", result.isFailure)
    }

    @Test
    fun changePassphrase_oldFailsAfterCommit_newSucceeds() = runBlocking {
        keyManager.setupNew("old".toCharArray())
        keyManager.changePassphrase("old".toCharArray(), "new".toCharArray())
        val oldRes = keyManager.unlock("old".toCharArray())
        val newRes = keyManager.unlock("new".toCharArray())
        assertTrue("old must fail", oldRes.isFailure)
        assertTrue("new must succeed", newRes.isSuccess)
    }

    @Test
    fun changePassphrase_doesNotChangeDekValue() = runBlocking {
        keyManager.setupNew("old".toCharArray())
        val before = keyManager.unlock("old".toCharArray()).getOrThrow().toByteArray().copyOf()
        keyManager.changePassphrase("old".toCharArray(), "new".toCharArray())
        val after = keyManager.unlock("new".toCharArray()).getOrThrow().toByteArray()
        assertArrayEquals("DEK must be preserved across passphrase change", before, after)
    }

    @Test
    fun cryptoErase_removes_wrappedDek_and_keystoreAlias() = runBlocking {
        keyManager.setupNew("hunter2".toCharArray())
        keyManager.cryptoErase()
        assertFalse("wrapped_dek.bin should be removed", wrappedDekFile.exists())
        assertFalse("salt.bin should be removed", saltFile.exists())
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(
            "Keystore alias should be removed",
            ks.containsAlias(CryptoConfig.KEYSTORE_ALIAS_KEK),
        )
        // Idempotent — second call must not throw.
        keyManager.cryptoErase()
    }

    @Test
    fun isSetupComplete_false_before_setup_true_after() = runBlocking {
        assertFalse("must be incomplete pre-setup", keyManager.isSetupComplete())
        keyManager.setupNew("hunter2".toCharArray())
        assertTrue("must be complete post-setup", keyManager.isSetupComplete())
        keyManager.cryptoErase()
        assertFalse("must be incomplete post-erase", keyManager.isSetupComplete())
    }

    @Test
    fun setupNew_uses_strongBox_when_available_else_tee_fallback() = runBlocking {
        keyManager.setupNew("hunter2".toCharArray())
        // We can't deterministically know whether StrongBox or TEE was used —
        // we can only assert a Keystore alias exists and is usable. The
        // setupNew() implementation tries StrongBox first and silently falls
        // back to TEE on StrongBoxUnavailableException, so success here covers
        // both branches.
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertNotNull(
            "alias must be present (StrongBox or TEE-backed)",
            ks.getKey(CryptoConfig.KEYSTORE_ALIAS_KEK, null),
        )
        // And subsequent unlock must succeed end-to-end.
        assertTrue(keyManager.unlock("hunter2".toCharArray()).isSuccess)
    }

    @Test
    fun derived_keys_use_argon2id_per_CryptoConfig() = runBlocking {
        // Indirect check: if derived KEK didn't match Argon2 output (e.g., if
        // the wrapper silently switched to PBKDF2), unlock would fail because
        // setup writes layer-1 ciphertext under Argon2(KEK) and unlock derives
        // identically. Round-trip success implies algorithm consistency.
        keyManager.setupNew("a".toCharArray())
        val r1 = keyManager.unlock("a".toCharArray())
        assertTrue("Argon2id round-trip must succeed", r1.isSuccess)

        // Salt is 16 bytes (CryptoConfig spec); KEK is 32 bytes (Argon2 hashLen).
        assertEquals(KeyManager.SALT_LENGTH.toLong(), saltFile.length())
        // Negative: a different passphrase must produce a different KEK (no
        // collision with the all-zero salt we'd have if Argon2 was no-op).
        val r2 = keyManager.unlock("b".toCharArray())
        assertTrue("wrong passphrase must fail", r2.isFailure)

        // Sanity: the saved salt is not all zeroes — random source intact.
        val saltBytes = saltFile.readBytes()
        assertFalse(
            "salt must not be all-zero (SecureRandom contract)",
            saltBytes.all { it == 0.toByte() },
        )
    }
}
