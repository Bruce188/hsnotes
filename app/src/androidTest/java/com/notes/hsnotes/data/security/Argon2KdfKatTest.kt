package com.notes.hsnotes.data.security

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.lambdapioneer.argon2kt.Argon2Version
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Argon2id passthrough KAT for [Argon2Kdf].
 *
 * RFC 9106 Appendix B specifies test vectors that include `secret` (key) and
 * `additionalData`; the upstream `argon2kt` 1.5.0 high-level API does not
 * expose those inputs, so we cannot reproduce the raw RFC vector through this
 * wrapper. Instead, the [rfc9106_appendix_b_kat_vector_argon2id] case asserts
 * that this wrapper produces byte-for-byte identical output to a direct
 * `Argon2Kt.hash(...)` call with the same parameters — RFC 9106 compliance is
 * inherited from argon2kt's own KAT suite (run on every release of that lib).
 *
 * Lives in `androidTest/` because argon2kt loads a JNI .so at first hash().
 */
class Argon2KdfKatTest {

    private val kdf = Argon2Kdf()

    // Reduced KAT params: 64MB / t=1 / p=1 keeps the emulator under one second
    // per derivation while exercising the full code path. The floor in
    // [Argon2Params] forbids dropping below 64MB.
    private val katParams = Argon2Params(memoryKiB = 64 * 1024, iterations = 1, parallelism = 1)

    private val katPassword = "password".toCharArray()
    private val katSalt = "somesalt00000000".toByteArray(Charsets.UTF_8) // 16 bytes

    @Test
    fun rfc9106_appendix_b_kat_vector_argon2id() {
        val direct = Argon2Kt().hash(
            mode = Argon2Mode.ARGON2_ID,
            password = "password".toByteArray(Charsets.UTF_8),
            salt = katSalt,
            tCostInIterations = katParams.iterations,
            mCostInKibibyte = katParams.memoryKiB,
            parallelism = katParams.parallelism,
            hashLengthInBytes = Argon2Kdf.HASH_LENGTH_BYTES,
            version = Argon2Version.V13,
        ).rawHashAsByteArray()

        val viaWrapper = kdf.derive(katPassword.copyOf(), katSalt.copyOf(), katParams)

        assertArrayEquals(
            "Wrapper diverged from direct argon2kt output",
            direct,
            viaWrapper,
        )
        assertEquals(32, viaWrapper.size)
    }

    @Test
    fun derive_returns_32B_key() {
        val out = kdf.derive("anything".toCharArray(), ByteArray(16) { it.toByte() }, katParams)
        assertEquals(32, out.size)
    }

    @Test
    fun derive_is_deterministic_for_same_inputs() {
        val salt = ByteArray(16) { 0x42.toByte() }
        val a = kdf.derive("hunter2".toCharArray(), salt.copyOf(), katParams)
        val b = kdf.derive("hunter2".toCharArray(), salt.copyOf(), katParams)
        assertArrayEquals(a, b)
    }

    @Test
    fun derive_differs_with_different_salt() {
        val s1 = ByteArray(16) { 0x11.toByte() }
        val s2 = ByteArray(16) { 0x22.toByte() }
        val a = kdf.derive("hunter2".toCharArray(), s1, katParams)
        val b = kdf.derive("hunter2".toCharArray(), s2, katParams)
        assertNotEquals(
            "different salts must yield different output",
            a.toList(),
            b.toList(),
        )
    }

    @Test
    fun derive_wipes_passphrase_after_call() {
        val pw = "topsecret".toCharArray()
        kdf.derive(pw, ByteArray(16), katParams)
        assertTrue(
            "passphrase CharArray was not wiped after derive",
            pw.all { it == ' ' },
        )
        assertFalse("expected wipe", pw.any { it == 't' || it == 'o' || it == 'p' })
    }

    @Test
    fun derive_with_corrupt_salt_throws() {
        try {
            kdf.derive("anything".toCharArray(), ByteArray(15), katParams)
            fail("expected IllegalArgumentException for short salt")
        } catch (e: IllegalArgumentException) {
            assertTrue(
                "exception message must mention salt length",
                e.message!!.contains("16 bytes"),
            )
        }
    }
}
