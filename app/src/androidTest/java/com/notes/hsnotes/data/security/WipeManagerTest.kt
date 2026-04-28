package com.notes.hsnotes.data.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore

/**
 * On-device coverage for [WipeManager]. Plan §7.1 Tests block.
 *
 * Each test seeds a real KeyManager (so a wrapped DEK + Keystore alias exist),
 * runs the requested [WipeLevel], then asserts the on-disk + Keystore + lock
 * side effects.
 */
@RunWith(AndroidJUnit4::class)
class WipeManagerTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val keyManager = KeyManager(context, params = Argon2Params(memoryKiB = 64 * 1024, iterations = 1, parallelism = 1))

    @Before
    fun seed() = runBlocking {
        // Fresh setup before each test so the wrapped DEK + Keystore alias exist.
        runCatching { keyManager.cryptoErase() }
        keyManager.setupNew("seed-passphrase".toCharArray())
    }

    @After
    fun tearDown() = runBlocking {
        runCatching { keyManager.cryptoErase() }
    }

    @Test
    fun cryptoErase_overwrites_wrappedDek_with_random_bytes_then_deletes_file() = runBlocking {
        val secDir = File(context.filesDir, CryptoConfig.SEC_DIR_NAME)
        val wrapped = File(secDir, CryptoConfig.WRAPPED_DEK_FILENAME)
        assertTrue("setup must produce wrapped_dek.bin", wrapped.exists())

        WipeManager(context, keyManager).wipeNow(WipeLevel.CRYPTO_ERASE)

        assertFalse("wrapped_dek.bin must be unlinked post-cryptoErase", wrapped.exists())
    }

    @Test
    fun cryptoErase_deletes_keystore_alias() = runBlocking {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("setup must provision the KEK alias", ks.containsAlias(CryptoConfig.KEYSTORE_ALIAS_KEK))

        WipeManager(context, keyManager).wipeNow(WipeLevel.CRYPTO_ERASE)

        val ks2 = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse("KEK alias must be gone post-cryptoErase", ks2.containsAlias(CryptoConfig.KEYSTORE_ALIAS_KEK))
    }

    @Test
    fun cryptoErase_subsequent_unlock_fails_even_with_correct_passphrase() = runBlocking {
        WipeManager(context, keyManager).wipeNow(WipeLevel.CRYPTO_ERASE)

        val result = keyManager.unlock("seed-passphrase".toCharArray())
        assertTrue("post-erase unlock must fail", result.isFailure)
    }

    @Test
    fun nuclear_wipe_also_deletes_dbFiles_and_prefs_and_exports() = runBlocking {
        // Plant fakes that NUCLEAR must remove.
        val db = context.getDatabasePath("notes.db").apply { parentFile?.mkdirs(); writeBytes(byteArrayOf(1, 2, 3)) }
        val securePrefs = File(context.filesDir, "secure_prefs.json").apply { writeBytes(byteArrayOf(4)) }
        val exportsDir = File(context.filesDir, "exports").apply { mkdirs(); File(this, "x.json").writeBytes(byteArrayOf(5)) }

        WipeManager(context, keyManager).wipeNow(WipeLevel.NUCLEAR)

        assertFalse("notes.db must be unlinked", db.exists())
        assertFalse("secure_prefs.json must be unlinked", securePrefs.exists())
        assertFalse("exports/ must be unlinked", exportsDir.exists())
    }

    @Test
    fun lock_level_zeroizes_in_memory_only_no_disk_change() = runBlocking {
        val secDir = File(context.filesDir, CryptoConfig.SEC_DIR_NAME)
        val wrapped = File(secDir, CryptoConfig.WRAPPED_DEK_FILENAME)
        val priorBytes = wrapped.readBytes()

        var lockCalls = 0
        var uiLockCalls = 0
        val wm = WipeManager(
            context = context,
            keyManager = keyManager,
            onLock = { lockCalls += 1 },
            onUiLock = { uiLockCalls += 1 },
        )

        wm.wipeNow(WipeLevel.LOCK)

        assertTrue("LOCK must not unlink wrapped_dek.bin", wrapped.exists())
        assertTrue("LOCK must not mutate wrapped_dek.bin", priorBytes.contentEquals(wrapped.readBytes()))
        assertEquals(1, lockCalls)
        assertEquals(1, uiLockCalls)
    }

    @Test
    fun soft_level_does_cryptoErase_and_locks_ui() = runBlocking {
        val secDir = File(context.filesDir, CryptoConfig.SEC_DIR_NAME)
        val wrapped = File(secDir, CryptoConfig.WRAPPED_DEK_FILENAME)

        var lockCalls = 0
        var uiLockCalls = 0
        val wm = WipeManager(
            context = context,
            keyManager = keyManager,
            onLock = { lockCalls += 1 },
            onUiLock = { uiLockCalls += 1 },
        )

        wm.wipeNow(WipeLevel.SOFT)

        assertFalse("SOFT must cryptoErase the wrapped_dek.bin", wrapped.exists())
        assertEquals(1, lockCalls)
        assertEquals(1, uiLockCalls)
    }
}
