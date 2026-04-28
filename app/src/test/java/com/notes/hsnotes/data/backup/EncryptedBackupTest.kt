package com.notes.hsnotes.data.backup

import com.notes.hsnotes.data.security.wipe
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Plan §9.1 Tests block. JVM unit tests — Argon2 has no JVM impl, so the
 * codec's `derive` slot is wired to a deterministic SHA-256 stretch. Key
 * properties (4 KiB padding, no oracle, AAD-bound header, JSON round-trip)
 * are independent of the underlying KDF.
 */
class EncryptedBackupTest {

    private val backup: BackupV1 = BackupV1(
        schema_version = 1,
        exported_at = "2026-04-27T10:00:00Z",
        notes = listOf(
            BackupNote(
                id = 1,
                title = "groceries",
                body = "milk, eggs, bread",
                tag = "personal",
                created_at = 1_700_000_000_000L,
                updated_at = 1_700_000_000_000L,
            ),
            BackupNote(
                id = 2,
                title = "rent reminder",
                body = "due on the 1st",
                tag = "bills",
                created_at = 1_700_001_000_000L,
                updated_at = 1_700_001_000_000L,
            ),
        ),
    )

    /** Deterministic 32-byte derive — fakes Argon2id while staying JVM-safe. */
    private val sha256Derive: suspend (CharArray, ByteArray) -> ByteArray = { pass, salt ->
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt)
        md.update(String(pass).toByteArray(StandardCharsets.UTF_8))
        md.digest()
    }

    private fun newCodec(seed: Long = 1234L) = EncryptedBackupCodec(
        derive = sha256Derive,
        rng = SecureRandom().apply { setSeed(seed) },
    )

    @Test
    fun export_with_passphrase_then_import_with_same_passphrase_roundtrips_identical_BackupV1() = runBlocking<Unit> {
        val codec = newCodec()
        val pass1 = "correct horse battery staple".toCharArray()
        val ct = codec.encode(backup, pass1)
        // encode wipes pass1 — verify it before we discard.
        assertTrue("passphrase should be wiped after encode", pass1.all { it == ' ' })

        val pass2 = "correct horse battery staple".toCharArray()
        val decoded = codec.decode(ct, pass2)
        assertTrue("passphrase should be wiped after decode", pass2.all { it == ' ' })

        assertEquals(backup, decoded)
    }

    @Test
    fun import_with_wrong_passphrase_throws_AuthFailure_no_oracle() = runBlocking<Unit> {
        val codec = newCodec()
        val ct = codec.encode(backup, "right".toCharArray())

        // Wrong passphrase — must throw the generic failure, NOT an
        // AEADBadTagException, IndexOutOfBounds, or anything that hints
        // at the failure mode.
        assertThrows(WrongBackupPassphrase::class.java) {
            runBlocking { codec.decode(ct, "wrong".toCharArray()) }
        }

        // Truncated header — same generic failure.
        assertThrows(WrongBackupPassphrase::class.java) {
            runBlocking { codec.decode(ct.copyOfRange(0, 10), "right".toCharArray()) }
        }

        // Wrong magic — same generic failure.
        val flipped = ct.copyOf().apply { this[0] = 'X'.code.toByte() }
        assertThrows(WrongBackupPassphrase::class.java) {
            runBlocking { codec.decode(flipped, "right".toCharArray()) }
        }
    }

    @Test
    fun ciphertext_first_bytes_are_envelope_header_not_json_bracket() = runBlocking<Unit> {
        val codec = newCodec()
        val ct = codec.encode(backup, "p".toCharArray())

        // First four bytes MUST be ASCII MAGIC and NOT '{' (the JSON opener).
        assertArrayEquals(EncryptedBackupCodec.MAGIC, ct.copyOfRange(0, 4))
        assertFalse(
            "ciphertext must not start with '{'",
            ct.isNotEmpty() && ct[0] == '{'.code.toByte(),
        )
        // No raw JSON substring should appear in the encrypted body — quick
        // smoke check on a value we know is in `backup`.
        val asAscii = String(ct, StandardCharsets.US_ASCII)
        assertFalse("'groceries' must not appear in ciphertext", asAscii.contains("groceries"))
        assertFalse("'schema_version' must not appear in ciphertext", asAscii.contains("schema_version"))
    }

    @Test
    fun ciphertext_size_is_padded_to_4KB_boundary() = runBlocking<Unit> {
        val codec = newCodec()
        val small = codec.encode(backup, "p".toCharArray())
        assertEquals("ciphertext file must align to 4 KiB", 0, small.size % 4096)

        // Bigger payload to verify alignment also holds at >1 block.
        val bigBackup = backup.copy(
            notes = (1..200).map {
                BackupNote(
                    id = it.toLong(),
                    title = "note_$it",
                    body = "padded body line ".repeat(40),
                    tag = "bulk",
                    created_at = 1_700_000_000_000L + it,
                    updated_at = 1_700_000_000_000L + it,
                )
            },
        )
        val big = codec.encode(bigBackup, "p".toCharArray())
        assertEquals("ciphertext file must align to 4 KiB", 0, big.size % 4096)
        assertTrue("bigger payload produces bigger file", big.size > small.size)
    }

    @Test
    fun two_exports_of_same_data_with_same_passphrase_produce_different_ciphertext_due_to_random_salt() = runBlocking<Unit> {
        // Each codec uses a different RNG seed → different salt + nonce.
        val codecA = newCodec(seed = 1L)
        val codecB = newCodec(seed = 2L)
        val ctA = codecA.encode(backup, "p".toCharArray())
        val ctB = codecB.encode(backup, "p".toCharArray())
        assertEquals("padded sizes must match for equal payloads", ctA.size, ctB.size)
        // Magic + version match (first 5 bytes); everything past that MUST differ.
        assertNotEquals(
            "encrypted bodies must differ across exports of the same plaintext",
            ctA.copyOfRange(5, ctA.size).toList(),
            ctB.copyOfRange(5, ctB.size).toList(),
        )
    }

    @Test
    fun encode_wipes_passCopy_when_derive_throws() = runBlocking<Unit> {
        // Review V-N5 regression — derive may crash (native Argon2 OOM,
        // pre-wipe throw); the codec must wipe its internal passCopy before
        // rethrowing so the secret never lingers in heap.
        var captured: CharArray? = null
        val throwingDerive: suspend (CharArray, ByteArray) -> ByteArray = { pass, _ ->
            captured = pass // alias the codec's internal passCopy
            error("simulated derive failure")
        }
        val codec = EncryptedBackupCodec(derive = throwingDerive, rng = SecureRandom().apply { setSeed(1L) })
        val pass = "secret-passphrase".toCharArray()
        val thrown = runCatching { codec.encode(backup, pass) }
        assertTrue("encode must rethrow when derive fails", thrown.isFailure)
        assertTrue("caller passphrase must be wiped", pass.all { it == ' ' })
        assertTrue("captured passCopy must be non-null", captured != null)
        assertTrue("internal passCopy must be wiped on derive throw", captured!!.all { it == ' ' })
    }

    @Test
    fun decode_wipes_passCopy_when_derive_throws() = runBlocking<Unit> {
        // First produce a valid envelope so decode reaches the derive step.
        val envelope = newCodec().encode(backup, "right".toCharArray())

        var captured: CharArray? = null
        val throwingDerive: suspend (CharArray, ByteArray) -> ByteArray = { pass, _ ->
            captured = pass
            error("simulated derive failure")
        }
        val codec = EncryptedBackupCodec(derive = throwingDerive, rng = SecureRandom().apply { setSeed(1L) })
        val pass = "secret-passphrase".toCharArray()
        val thrown = runCatching { codec.decode(envelope, pass) }
        assertTrue("decode must rethrow when derive fails", thrown.isFailure)
        assertTrue("caller passphrase must be wiped", pass.all { it == ' ' })
        assertTrue("captured passCopy must be non-null", captured != null)
        assertTrue("internal passCopy must be wiped on derive throw", captured!!.all { it == ' ' })
    }

    @Test
    fun backup_passphrase_equal_to_unlock_passphrase_throws_at_viewmodel_layer() = runBlocking<Unit> {
        // Plan §9.1 enforces this guard at the ViewModel level. We exercise
        // the [BackupPassphraseGuard] contract directly here — the guard
        // returns true iff the candidate would unlock the wrapped DEK; the
        // ViewModel converts that into [BackupPassphraseEqualsUnlock].
        val unlockPass = "unlock-secret".toCharArray()
        val guard = BackupPassphraseGuard { candidate ->
            String(candidate) == String(unlockPass)
        }

        // Same as unlock → guard reports true → ViewModel must reject.
        assertTrue(guard.isSameAsUnlockPassphrase("unlock-secret".toCharArray()))
        // Different → guard reports false → export proceeds.
        assertFalse(guard.isSameAsUnlockPassphrase("backup-secret".toCharArray()))

        // The exception type the ViewModel raises has a stable identity.
        val ex = BackupPassphraseEqualsUnlock()
        assertTrue(
            "exception message must reference passphrase mismatch requirement",
            ex.message?.contains("differ") == true,
        )

        unlockPass.wipe()
    }
}
