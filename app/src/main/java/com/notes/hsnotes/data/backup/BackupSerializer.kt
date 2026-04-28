package com.notes.hsnotes.data.backup

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * JSON backup format v1. Field names are snake_case for human readability;
 * Kotlin properties match the spec exactly so the wire format stays stable.
 */
@Serializable
data class BackupV1(
    val schema_version: Int = 1,
    val exported_at: String,
    val notes: List<BackupNote>
)

@Serializable
data class BackupNote(
    val id: Long,
    val title: String,
    val body: String,
    val tag: String? = null,
    val created_at: Long,
    val updated_at: Long
)

object BackupSerializer {

    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    fun encode(backup: BackupV1): String = json.encodeToString(BackupV1.serializer(), backup)

    /**
     * Parse and validate a backup. Throws if:
     *  - schema_version is not 1
     *  - any note has updated_at < created_at
     */
    fun decode(text: String): BackupV1 {
        val parsed = json.decodeFromString(BackupV1.serializer(), text)
        require(parsed.schema_version == 1) {
            "Unsupported backup schema version ${parsed.schema_version} (this app supports v1 only)"
        }
        parsed.notes.forEach {
            require(it.updated_at >= it.created_at) {
                "Note ${it.id} has updated_at < created_at"
            }
        }
        return parsed
    }
}
