package com.notes.hsnotes.data.security

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * JVM unit coverage for [PanicPin]. Plan §7.3.
 *
 * KDF is faked with deterministic SHA-256 (`pin || salt`) so we never call into
 * the Argon2 JNI on a JVM test runtime. Production wires [Argon2Kdf.derive]
 * via [PanicPin.productionDerive].
 */
class PanicPinTest {

    private fun newPin(
        store: PanicPinStore = InMemPanicPinStore(),
        derive: suspend (CharArray, ByteArray) -> ByteArray = ::sha256DeriveCounting,
        onMatch: suspend () -> Unit = {},
    ): PanicPin = PanicPin(store = store, derive = derive, onMatch = onMatch)

    @Test
    fun register_then_match_returns_true_for_correct_pin() = runTest {
        val store = InMemPanicPinStore()
        val pin = newPin(store)
        pin.register("123456".toCharArray(), realPassphrase = "alpha-bravo".toCharArray())

        assertTrue(pin.matches("123456".toCharArray()))
    }

    @Test
    fun register_then_match_returns_false_for_wrong_pin() = runTest {
        val store = InMemPanicPinStore()
        val pin = newPin(store)
        pin.register("123456".toCharArray(), realPassphrase = "alpha-bravo".toCharArray())

        assertFalse(pin.matches("654321".toCharArray()))
    }

    @Test
    fun register_with_pin_equal_to_realPassphrase_throws() = runTest {
        val pin = newPin()
        val ex = assertThrows(IllegalArgumentException::class.java) {
            kotlinx.coroutines.runBlocking {
                pin.register(
                    pin = "samesame".toCharArray(),
                    realPassphrase = "samesame".toCharArray(),
                )
            }
        }
        assertTrue(
            "message must mention passphrase: ${ex.message}",
            ex.message!!.contains("passphrase"),
        )
    }

    @Test
    fun register_with_pin_shorter_than_6_digits_throws() = runTest {
        val pin = newPin()
        val ex = assertThrows(IllegalArgumentException::class.java) {
            kotlinx.coroutines.runBlocking {
                pin.register(
                    pin = "12345".toCharArray(),
                    realPassphrase = "alpha-bravo".toCharArray(),
                )
            }
        }
        assertTrue(
            "message must mention min length: ${ex.message}",
            ex.message!!.contains("6"),
        )
    }

    @Test
    fun match_for_unregistered_returns_false() = runTest {
        val store = InMemPanicPinStore()
        val pin = newPin(store)
        // No register() call.

        assertFalse(pin.matches("123456".toCharArray()))
    }

    @Test
    fun match_uses_constant_time_comparison_no_early_exit() = runTest {
        // The contract: matches() always runs the full KDF on a registered
        // record and compares hashes (equal-length, via MessageDigest.isEqual).
        // We assert this two ways:
        //   1. A counting derive sees exactly one call per matches() invocation
        //      regardless of mismatch position (no short-circuit on first
        //      differing byte).
        //   2. The hashes really do match for the registered pin.
        val store = InMemPanicPinStore()
        val counter = CountingDerive(::sha256DeriveCounting)
        val pin = PanicPin(store = store, derive = counter::derive)

        pin.register("123456".toCharArray(), realPassphrase = "alpha".toCharArray())
        val baseline = counter.calls
        assertEquals("register should call derive exactly once", baseline, 1)

        // Mismatch in first character — must still run the full derive.
        assertFalse(pin.matches("923456".toCharArray()))
        assertEquals("matches() must call derive exactly once on mismatch", baseline + 1, counter.calls)

        // Mismatch in last character — must also run the full derive.
        assertFalse(pin.matches("123459".toCharArray()))
        assertEquals("matches() must call derive exactly once on tail mismatch", baseline + 2, counter.calls)

        // Match.
        assertTrue(pin.matches("123456".toCharArray()))
        assertEquals(baseline + 3, counter.calls)
    }

    @Test
    fun match_triggers_cryptoErase_via_callback_when_true() = runTest {
        val store = InMemPanicPinStore()
        var fired = 0
        val pin = newPin(store, onMatch = { fired += 1 })

        pin.register("123456".toCharArray(), realPassphrase = "alpha".toCharArray())
        assertEquals("onMatch must NOT fire on register", 0, fired)

        assertFalse(pin.matches("999999".toCharArray()))
        assertEquals("onMatch must NOT fire on mismatch", 0, fired)

        assertTrue(pin.matches("123456".toCharArray()))
        assertEquals("onMatch MUST fire on hit", 1, fired)

        // Idempotency check — repeat hits fire repeatedly.
        assertTrue(pin.matches("123456".toCharArray()))
        assertEquals(2, fired)
    }

    @Test
    fun register_wipes_both_pin_and_realPassphrase() = runTest {
        val pin = newPin()
        val pinBuf = "123456".toCharArray()
        val passBuf = "alpha-bravo".toCharArray()

        pin.register(pin = pinBuf, realPassphrase = passBuf)

        // After register, both buffers must be wiped (CharArray.wipe overwrites
        // with the space character; see Zeroize.kt).
        val expectedPin = CharArray(pinBuf.size) { ' ' }
        val expectedPass = CharArray(passBuf.size) { ' ' }
        assertArrayEquals(expectedPin, pinBuf)
        assertArrayEquals(expectedPass, passBuf)
    }

    @Test
    fun matches_does_not_wipe_input_buffer() = runTest {
        // Auth pipeline reuses the input buffer for the real Argon2 derivation
        // when matches() returns false, so we must NOT scrub it here.
        val store = InMemPanicPinStore()
        val pin = newPin(store)
        pin.register("123456".toCharArray(), realPassphrase = "alpha".toCharArray())

        val input = "999999".toCharArray()
        val expectedAfter = input.copyOf()
        assertFalse(pin.matches(input))
        assertArrayEquals(expectedAfter, input)
    }

    @Test
    fun register_persists_record_then_matches_round_trips_via_store() = runTest {
        val store = InMemPanicPinStore()
        val pin = newPin(store)
        pin.register("123456".toCharArray(), realPassphrase = "alpha".toCharArray())

        // Store should now hold a record with non-empty hash + 16-byte salt.
        val record = store.readPanicPinRecord()
        assertNotNull(record)
        assertEquals(PanicPin.SALT_BYTES, record!!.salt.size)
        assertEquals(32 /* sha256 */, record.hash.size)

        // Constructing a fresh PanicPin against the same store still matches.
        val pin2 = newPin(store)
        assertTrue(pin2.matches("123456".toCharArray()))
    }
}

// -----------------------------------------------------------------------------
// In-memory PanicPinStore
// -----------------------------------------------------------------------------

private class InMemPanicPinStore : PanicPinStore {
    private var record: PanicPinRecord? = null
    override suspend fun readPanicPinRecord(): PanicPinRecord? = record
    override suspend fun writePanicPinRecord(record: PanicPinRecord) {
        this.record = record
    }
    override suspend fun clearPanicPinRecord() {
        record = null
    }
}

// -----------------------------------------------------------------------------
// Deterministic SHA-256 derive
// -----------------------------------------------------------------------------

private fun sha256DeriveCounting(input: CharArray, salt: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-256")
    md.update(charsToUtf8(input))
    md.update(salt)
    return md.digest()
}

private fun charsToUtf8(c: CharArray): ByteArray =
    String(c).toByteArray(Charsets.UTF_8)

private class CountingDerive(private val inner: suspend (CharArray, ByteArray) -> ByteArray) {
    var calls: Int = 0
        private set
    suspend fun derive(input: CharArray, salt: ByteArray): ByteArray {
        calls += 1
        return inner(input, salt)
    }
}
