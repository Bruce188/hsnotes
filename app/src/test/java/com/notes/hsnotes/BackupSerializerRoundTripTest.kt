package com.notes.hsnotes

import com.notes.hsnotes.data.backup.BackupNote
import com.notes.hsnotes.data.backup.BackupSerializer
import com.notes.hsnotes.data.backup.BackupV1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class BackupSerializerRoundTripTest {

    private fun sampleBackup(): BackupV1 = BackupV1(
        schema_version = 1,
        exported_at = "2026-04-26T10:00:00Z",
        notes = listOf(
            BackupNote(
                id = 1,
                title = "Shopping list",
                body = "milk, eggs",
                tag = "personal",
                created_at = 1_700_000_000_000L,
                updated_at = 1_700_000_500_000L,
            ),
            BackupNote(
                id = 2,
                title = "",
                body = "untitled scratch",
                tag = null,
                created_at = 1_700_001_000_000L,
                updated_at = 1_700_001_000_000L,
            ),
        )
    )

    @Test
    fun encodeThenDecode_preservesAllFields() {
        val original = sampleBackup()
        val text = BackupSerializer.encode(original)
        val parsed = BackupSerializer.decode(text)
        assertEquals(original, parsed)
    }

    @Test
    fun encode_producesPrettyJsonContainingExpectedKeys() {
        val text = BackupSerializer.encode(sampleBackup())
        // snake_case keys per spec
        listOf(
            "\"schema_version\"",
            "\"exported_at\"",
            "\"notes\"",
            "\"title\"",
            "\"body\"",
            "\"tag\"",
            "\"created_at\"",
            "\"updated_at\"",
        ).forEach { key ->
            assert(text.contains(key)) { "Missing key $key in encoded JSON: $text" }
        }
    }

    @Test
    fun decode_rejectsUnsupportedSchemaVersion() {
        val v2Text = """
            {
              "schema_version": 2,
              "exported_at": "2026-04-26T10:00:00Z",
              "notes": []
            }
        """.trimIndent()
        assertThrows(IllegalArgumentException::class.java) {
            BackupSerializer.decode(v2Text)
        }
    }

    @Test
    fun decode_rejectsUpdatedBeforeCreated() {
        val bad = """
            {
              "schema_version": 1,
              "exported_at": "2026-04-26T10:00:00Z",
              "notes": [{
                "id": 1, "title": "x", "body": "y",
                "created_at": 100, "updated_at": 50
              }]
            }
        """.trimIndent()
        assertThrows(IllegalArgumentException::class.java) {
            BackupSerializer.decode(bad)
        }
    }

    @Test
    fun decode_ignoresUnknownTopLevelKeys() {
        // ignoreUnknownKeys = true on the Json instance
        val withExtra = """
            {
              "schema_version": 1,
              "future_field": "ignored",
              "exported_at": "2026-04-26T10:00:00Z",
              "notes": []
            }
        """.trimIndent()
        val parsed = BackupSerializer.decode(withExtra)
        assertEquals(1, parsed.schema_version)
    }
}
