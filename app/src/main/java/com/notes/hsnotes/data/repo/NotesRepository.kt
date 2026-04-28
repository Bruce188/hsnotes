package com.notes.hsnotes.data.repo

import androidx.room.withTransaction
import com.notes.hsnotes.data.backup.BackupNote
import com.notes.hsnotes.data.backup.BackupSerializer
import com.notes.hsnotes.data.backup.BackupV1
import com.notes.hsnotes.data.db.AppDatabase
import com.notes.hsnotes.data.db.NoteDao
import com.notes.hsnotes.data.db.entity.NoteEntity
import kotlinx.coroutines.flow.Flow
import java.time.Instant
import java.time.format.DateTimeFormatter

/**
 * Single point of access for the notes table. Wraps [NoteDao] so the UI layer
 * never sees Room types directly; also owns timestamp policy (`createdAt` /
 * `updatedAt`) and the backup encode/decode bridge.
 *
 * Plan §3.1 — installed by [com.notes.hsnotes.App.installDatabase] after
 * successful unlock. Pre-unlock callers see [com.notes.hsnotes.data.db.LockedException]
 * via [com.notes.hsnotes.App.repository].
 *
 * Production callers should use [fromDatabase] which wires [txRunner] to
 * Room's [androidx.room.withTransaction] extension. Tests construct the
 * primary constructor directly with a no-op [txRunner] to avoid pulling
 * in [AppDatabase] (which would trigger the SQLCipher native-library load
 * outside Android).
 */
class NotesRepository(
    private val noteDao: NoteDao,
    private val now: () -> Long = { System.currentTimeMillis() },
    private val txRunner: suspend (suspend () -> Unit) -> Unit,
) {

    /** Flow of all notes, most-recently-updated first. */
    val notes: Flow<List<NoteEntity>> = noteDao.observeAll()

    suspend fun load(id: Long): NoteEntity? = noteDao.byId(id)

    /**
     * Insert a new note or update an existing one.
     *
     * Caller passes a partially-populated [NoteEntity] (id == 0L for insert).
     * Timestamps are owned by the repository: [createdAt] is set on first
     * insert, [updatedAt] is always bumped to [now]. Returns the row id.
     */
    suspend fun upsert(note: NoteEntity): Long {
        val ts = now()
        return if (note.id == 0L) {
            noteDao.insert(note.copy(createdAt = ts, updatedAt = ts))
        } else {
            val existing = noteDao.byId(note.id)
            val createdAt = existing?.createdAt ?: ts
            noteDao.update(note.copy(createdAt = createdAt, updatedAt = ts))
            note.id
        }
    }

    suspend fun delete(id: Long) = noteDao.deleteById(id)

    suspend fun count(): Int = noteDao.count()

    // -------------------------------------------------------------------------
    // Backup bridge — serializer-agnostic; the encrypted-file layer wraps the
    // result of [buildBackup] with [com.notes.hsnotes.data.backup.EncryptedBackupCodec].
    // -------------------------------------------------------------------------

    suspend fun buildBackup(): BackupV1 {
        val all = noteDao.observeAllOnce()
        return BackupV1(
            schema_version = 1,
            exported_at = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(now())),
            notes = all.map { n ->
                BackupNote(
                    id = n.id,
                    title = n.title,
                    body = n.body,
                    tag = n.tag,
                    created_at = n.createdAt,
                    updated_at = n.updatedAt,
                )
            }
        )
    }

    /**
     * Replace the entire notes table with the rows in [backup].
     *
     * Used by the import-replace path (see [com.notes.hsnotes.ui.screens.settings.SettingsViewModel]).
     * Wrapped in [androidx.room.withTransaction] so a mid-loop failure rolls
     * back the wipe.
     */
    suspend fun replaceFromBackup(backup: BackupV1) {
        txRunner {
            noteDao.deleteAll()
            backup.notes.forEach { n ->
                noteDao.insert(
                    NoteEntity(
                        id = 0L,                  // re-key on import; ids are local
                        title = n.title,
                        body = n.body,
                        tag = n.tag,
                        createdAt = n.created_at,
                        updatedAt = n.updated_at,
                    )
                )
            }
        }
    }

    /**
     * Append the rows from [backup] to the existing table without touching
     * existing notes (merge path).
     */
    suspend fun mergeFromBackup(backup: BackupV1) {
        backup.notes.forEach { n ->
            noteDao.insert(
                NoteEntity(
                    id = 0L,
                    title = n.title,
                    body = n.body,
                    tag = n.tag,
                    createdAt = n.created_at,
                    updatedAt = n.updated_at,
                )
            )
        }
    }

    fun encodeBackup(backup: BackupV1): String = BackupSerializer.encode(backup)

    fun decodeBackup(text: String): BackupV1 = BackupSerializer.decode(text)

    companion object {
        /**
         * Production wiring. Binds [txRunner] to [database.withTransaction]
         * so [replaceFromBackup] runs atomically inside a Room transaction.
         */
        fun fromDatabase(
            database: AppDatabase,
            now: () -> Long = { System.currentTimeMillis() },
        ): NotesRepository = NotesRepository(
            noteDao = database.noteDao(),
            now = now,
            txRunner = { block -> database.withTransaction { block() } },
        )
    }
}
