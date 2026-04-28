package com.notes.hsnotes.data.security

import androidx.test.platform.app.InstrumentationRegistry
import com.notes.hsnotes.data.db.LockedException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * On-device coverage for [SecurePrefs] — Tink AEAD + DataStore.
 *
 * Plan §4.1 Tests block.
 */
class SecurePrefsTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private val dek: Dek = Dek(ByteArray(32) { 0x42.toByte() })

    private val secDir: File get() = File(context.filesDir, CryptoConfig.SEC_DIR_NAME)
    private val keysetFile: File get() = File(secDir, SecurePrefs.KEYSET_FILENAME)
    private val dataStoreFile: File get() = File(context.filesDir, "datastore/${SecurePrefs.DATASTORE_NAME}.preferences_pb")

    @Before
    fun cleanState() {
        if (secDir.exists()) secDir.deleteRecursively()
        runCatching { dataStoreFile.delete() }
    }

    @After
    fun tearDown() = cleanState()

    // -------------------------------------------------------------------------
    // 1. Encrypt-then-decrypt round-trip across all PrefKey flavors.
    // -------------------------------------------------------------------------
    @Test
    fun write_then_read_roundtrip_through_aead() = runBlocking {
        val prefs = SecurePrefs(context, dek)

        val sk = StringKey("user_label")
        val lk = LongKey("balance_cents")
        val ik = IntKey("counter")
        val bk = BoolKey("flag")
        val ak = ByteArrayKey("blob")

        prefs.set(sk, "hello-secure-world")
        prefs.set(lk, 50_00L)
        prefs.set(ik, 42)
        prefs.set(bk, true)
        prefs.set(ak, byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05))

        assertEquals("hello-secure-world", prefs.get(sk))
        assertEquals(50_00L, prefs.get(lk))
        assertEquals(42, prefs.get(ik))
        assertEquals(true, prefs.get(bk))
        assertArrayEquals(byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05), prefs.get(ak))

        // Absent key returns null.
        assertNull(prefs.get(StringKey("never_written")))
    }

    // -------------------------------------------------------------------------
    // 2. The on-disk Preferences file must NOT contain the raw plaintext.
    // -------------------------------------------------------------------------
    @Test
    fun prefs_file_is_high_entropy_no_plaintext_substring() = runBlocking {
        val prefs = SecurePrefs(context, dek)
        val needle = "PLAINTEXT-SHOULD-NOT-LEAK-${System.nanoTime()}"
        prefs.set(StringKey("leak_canary"), needle)
        // Force flush by reading back.
        assertEquals(needle, prefs.get(StringKey("leak_canary")))

        assertTrue("DataStore file must exist", dataStoreFile.exists())
        val raw = dataStoreFile.readBytes()
        val needleBytes = needle.toByteArray(Charsets.UTF_8)
        assertFalse(
            "DataStore file leaked plaintext substring '$needle'",
            indexOfSubarray(raw, needleBytes) >= 0,
        )
    }

    // -------------------------------------------------------------------------
    // 3. AES-GCM IV is randomized — same plaintext must produce distinct
    //    ciphertexts on repeated writes (ignoring DataStore deduplication
    //    by writing through different keys).
    // -------------------------------------------------------------------------
    @Test
    fun two_writes_of_same_value_produce_different_ciphertext_due_to_iv() = runBlocking {
        val prefs = SecurePrefs(context, dek)
        val plaintext = "same-value"
        val k1 = StringKey("iv_test_a")
        val k2 = StringKey("iv_test_b")
        prefs.set(k1, plaintext)
        prefs.set(k2, plaintext)
        // Read back round-trips.
        assertEquals(plaintext, prefs.get(k1))
        assertEquals(plaintext, prefs.get(k2))

        // Inspect the on-disk DataStore: locate the two ciphertext entries
        // by their key names. Both entries must hold different ciphertext
        // strings even though the plaintext was identical — this is the
        // randomized IV signature.
        val raw = dataStoreFile.readBytes()
        // The DataStore protobuf preserves the key name as plaintext; the
        // adjacent base64 ciphertext is what we check. We approximate by
        // finding both key names and asserting the bytes following each
        // differ (over a 64-byte window — enough to span the b64 ciphertext).
        val a = indexOfSubarray(raw, "iv_test_a".toByteArray(Charsets.UTF_8))
        val b = indexOfSubarray(raw, "iv_test_b".toByteArray(Charsets.UTF_8))
        assertTrue("key 'iv_test_a' must be present in datastore", a >= 0)
        assertTrue("key 'iv_test_b' must be present in datastore", b >= 0)

        val windowA = raw.copyOfRange(
            (a + "iv_test_a".length).coerceAtMost(raw.size),
            (a + "iv_test_a".length + 64).coerceAtMost(raw.size),
        )
        val windowB = raw.copyOfRange(
            (b + "iv_test_b".length).coerceAtMost(raw.size),
            (b + "iv_test_b".length + 64).coerceAtMost(raw.size),
        )
        assertNotEquals(
            "ciphertext after iv_test_a and iv_test_b must differ (randomized IV)",
            windowA.toList(),
            windowB.toList(),
        )
    }

    // -------------------------------------------------------------------------
    // 4. After dispose() — i.e., the DEK has been zeroized — every read or
    //    write must throw LockedException.
    // -------------------------------------------------------------------------
    @Test
    fun read_with_zeroized_dek_throws() = runBlocking {
        val prefs = SecurePrefs(context, dek)
        val k = StringKey("post_dispose")
        prefs.set(k, "value")
        assertNotNull(prefs.get(k))

        prefs.dispose()

        try {
            prefs.get(k)
            fail("expected LockedException after dispose() on get()")
        } catch (e: LockedException) {
            // expected
        }
        try {
            prefs.set(k, "another-value")
            fail("expected LockedException after dispose() on set()")
        } catch (e: LockedException) {
            // expected
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------
    private fun indexOfSubarray(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || needle.size > haystack.size) return -1
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}
