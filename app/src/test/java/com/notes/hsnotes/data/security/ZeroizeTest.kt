package com.notes.hsnotes.data.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ZeroizeTest {

    @Test
    fun ByteArray_wipe_overwritesAllBytes() {
        val secret = byteArrayOf(0x41, 0x53, -0x66, 0x12, 0x77, -0x01)
        secret.wipe()
        for ((i, b) in secret.withIndex()) {
            assertEquals("byte at $i not zeroed", 0.toByte(), b)
        }
    }

    @Test
    fun CharArray_wipe_overwritesAllChars() {
        val secret = "hunter2-correct-horse".toCharArray()
        secret.wipe()
        for ((i, c) in secret.withIndex()) {
            assertEquals("char at $i not overwritten", ' ', c)
        }
        // Defensive: no original character survived anywhere in the array.
        assertTrue(
            "wipe did not eliminate original content",
            secret.none { it != ' ' },
        )
    }

    @Test
    fun useThenWipe_wipesOnNormalExit() {
        val secret = byteArrayOf(1, 2, 3, 4, 5)
        val result = secret.useThenWipe(wipe = { wipe() }) { bytes ->
            // Inside the block, bytes are still readable.
            assertEquals(5, bytes.size)
            assertEquals(3.toByte(), bytes[2])
            "ok"
        }
        assertEquals("ok", result)
        assertTrue("ByteArray not wiped after normal exit", secret.all { it == 0.toByte() })
    }

    @Test
    fun useThenWipe_wipesOnExceptionExit() {
        val secret = "passphrase".toCharArray()
        val sentinel = RuntimeException("boom")
        try {
            secret.useThenWipe(wipe = { wipe() }) { _ ->
                throw sentinel
            }
            fail("expected exception was not thrown")
        } catch (t: RuntimeException) {
            assertEquals(sentinel, t)
        }
        assertTrue(
            "CharArray not wiped after exceptional exit",
            secret.all { it == ' ' },
        )
    }
}
