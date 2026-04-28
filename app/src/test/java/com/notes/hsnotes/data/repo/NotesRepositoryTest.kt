package com.notes.hsnotes.data.repo

import com.notes.hsnotes.data.backup.BackupNote
import com.notes.hsnotes.data.backup.BackupV1
import com.notes.hsnotes.data.db.NoteDao
import com.notes.hsnotes.data.db.entity.NoteEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * JVM unit-test coverage for [NotesRepository] focused on the bits that do
 * NOT touch Room's `withTransaction` extension: timestamp ownership in
 * [NotesRepository.upsert], snapshot construction in [NotesRepository.buildBackup],
 * and the load/delete/count delegation surface.
 *
 * `replaceFromBackup` / `mergeFromBackup` are exercised on-device — they
 * require a real Room database to honour `database.withTransaction`. The
 * fake DAO here intentionally does not stub that path.
 */
class NotesRepositoryTest {

    private fun newRepo(
        nowSeq: List<Long>,
        seed: List<NoteEntity> = emptyList(),
    ): Pair<NotesRepository, FakeNoteDao> {
        val dao = FakeNoteDao(seed = seed)
        val nowIter = nowSeq.iterator()
        // The primary constructor takes only the DAO + a now() clock + a
        // transaction runner; we pass an in-place runner that just invokes
        // the block. The on-device test exercises the real Room transaction
        // boundary via [NotesRepository.fromDatabase].
        val repo = NotesRepository(
            noteDao = dao,
            now = { if (nowIter.hasNext()) nowIter.next() else error("now() called more than expected") },
            txRunner = { block -> block() },
        )
        return repo to dao
    }

    @Test
    fun upsert_insert_sets_createdAt_and_updatedAt_to_now() = runBlocking {
        val (repo, dao) = newRepo(nowSeq = listOf(1_000L))
        val draft = NoteEntity(id = 0L, title = "t", body = "b", tag = null, createdAt = 0L, updatedAt = 0L)
        val id = repo.upsert(draft)
        val saved = dao.byId(id)!!
        assertEquals(1_000L, saved.createdAt)
        assertEquals(1_000L, saved.updatedAt)
    }

    @Test
    fun upsert_update_preserves_createdAt_and_bumps_updatedAt() = runBlocking {
        val initial = NoteEntity(id = 7L, title = "v1", body = "b", tag = null, createdAt = 100L, updatedAt = 100L)
        val (repo, dao) = newRepo(nowSeq = listOf(500L), seed = listOf(initial))
        repo.upsert(initial.copy(title = "v2"))
        val updated = dao.byId(7L)!!
        assertEquals("v2", updated.title)
        assertEquals(100L, updated.createdAt) // preserved
        assertEquals(500L, updated.updatedAt) // bumped to now()
    }

    @Test
    fun upsert_update_for_missing_row_uses_now_for_createdAt() = runBlocking {
        // Edge: caller passes id != 0 but no row exists. Defensive fallback —
        // createdAt becomes now(); upsert proceeds without crashing.
        val (repo, dao) = newRepo(nowSeq = listOf(900L))
        val draft = NoteEntity(id = 99L, title = "x", body = "y", tag = null, createdAt = 0L, updatedAt = 0L)
        repo.upsert(draft)
        val saved = dao.byId(99L)!!
        assertEquals(900L, saved.createdAt)
        assertEquals(900L, saved.updatedAt)
    }

    @Test
    fun load_delegates_to_dao() = runBlocking {
        val seed = NoteEntity(id = 1L, title = "a", body = "b", tag = "t", createdAt = 1L, updatedAt = 1L)
        val (repo, _) = newRepo(nowSeq = emptyList(), seed = listOf(seed))
        assertEquals(seed, repo.load(1L))
        assertNull(repo.load(2L))
    }

    @Test
    fun delete_removes_row() = runBlocking {
        val seed = NoteEntity(id = 1L, title = "a", body = "b", tag = null, createdAt = 1L, updatedAt = 1L)
        val (repo, dao) = newRepo(nowSeq = emptyList(), seed = listOf(seed))
        repo.delete(1L)
        assertNull(dao.byId(1L))
    }

    @Test
    fun count_reports_dao_count() = runBlocking {
        val seed = (1..3).map {
            NoteEntity(id = it.toLong(), title = "n$it", body = "", tag = null, createdAt = 1L, updatedAt = 1L)
        }
        val (repo, _) = newRepo(nowSeq = emptyList(), seed = seed)
        assertEquals(3, repo.count())
    }

    @Test
    fun buildBackup_uses_now_for_exported_at_and_serialises_all_rows() = runBlocking {
        val seed = listOf(
            NoteEntity(id = 1L, title = "first", body = "x", tag = null, createdAt = 100L, updatedAt = 200L),
            NoteEntity(id = 2L, title = "second", body = "y", tag = "tag", createdAt = 300L, updatedAt = 400L),
        )
        val (repo, _) = newRepo(nowSeq = listOf(1_700_000_000_000L), seed = seed)
        val backup = repo.buildBackup()
        assertEquals(1, backup.schema_version)
        assertNotNull(backup.exported_at)
        assertEquals(2, backup.notes.size)
        // Order matches DAO snapshot order — observeAllOnce returns
        // most-recently-updated first.
        assertEquals(
            listOf("second", "first"),
            backup.notes.map { it.title },
        )
        val first = backup.notes.first { it.title == "first" }
        assertEquals(100L, first.created_at)
        assertEquals(200L, first.updated_at)
        assertEquals(null, first.tag)
        val second = backup.notes.first { it.title == "second" }
        assertEquals("tag", second.tag)
    }

    @Test
    fun buildBackup_exported_at_is_iso_instant_format() = runBlocking {
        val (repo, _) = newRepo(nowSeq = listOf(1_700_000_000_000L))
        val backup = repo.buildBackup()
        // ISO-8601 instant: ends with `Z`, contains `T`.
        assertNotEquals("", backup.exported_at)
        assert(backup.exported_at.contains("T"))
        assert(backup.exported_at.endsWith("Z"))
    }

    @Test
    fun encodeBackup_then_decodeBackup_roundtrips() {
        val (repo, _) = newRepo(nowSeq = emptyList())
        val backup = BackupV1(
            schema_version = 1,
            exported_at = "2026-04-28T12:00:00Z",
            notes = listOf(
                BackupNote(id = 1L, title = "t", body = "b", tag = null, created_at = 1L, updated_at = 1L),
            ),
        )
        val text = repo.encodeBackup(backup)
        assertEquals(backup, repo.decodeBackup(text))
    }

    // -------------------------------------------------------------------------
    // Fakes
    // -------------------------------------------------------------------------

    private class FakeNoteDao(seed: List<NoteEntity> = emptyList()) : NoteDao {
        private val rows = LinkedHashMap<Long, NoteEntity>().also { m ->
            seed.forEach { m[it.id] = it }
        }
        private var nextId: Long = (seed.maxOfOrNull { it.id } ?: 0L) + 1L
        private val flow = MutableSharedFlow<List<NoteEntity>>(replay = 1)

        override fun observeAll(): Flow<List<NoteEntity>> = flow

        override suspend fun observeAllOnce(): List<NoteEntity> =
            rows.values.sortedByDescending { it.updatedAt }

        override suspend fun deleteAll() {
            rows.clear()
        }

        override suspend fun byId(id: Long): NoteEntity? = rows[id]

        override suspend fun insert(note: NoteEntity): Long {
            val id = if (note.id == 0L) nextId++ else note.id.also { if (it >= nextId) nextId = it + 1L }
            rows[id] = note.copy(id = id)
            return id
        }

        override suspend fun update(note: NoteEntity) {
            rows[note.id] = note
        }

        override suspend fun delete(note: NoteEntity) {
            rows.remove(note.id)
        }

        override suspend fun deleteById(id: Long) {
            rows.remove(id)
        }

        override suspend fun count(): Int = rows.size
    }
}

