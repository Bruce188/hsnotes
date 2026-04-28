package com.notes.hsnotes.data.db

import androidx.test.platform.app.InstrumentationRegistry
import com.notes.hsnotes.data.db.entity.NoteEntity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Coverage for [NoteDao] over a SQLCipher-backed [AppDatabase].
 * Each test owns its own DB filename so reruns cannot leak state.
 */
class NoteDaoTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dek: ByteArray = ByteArray(32) { 0x33.toByte() }
    private val testDbs = mutableListOf<String>()

    @Before
    fun setUp() {
        testDbs.clear()
    }

    @After
    fun tearDown() {
        testDbs.forEach { runCatching { context.deleteDatabase(it) } }
    }

    private fun freshDb(tag: String): AppDatabase {
        val name = "notedao_${tag}_${System.nanoTime()}.db"
        testDbs += name
        context.deleteDatabase(name)
        return AppDatabase.build(context, dek.copyOf(), name)
    }

    private fun newNote(title: String, ts: Long, tag: String? = null) = NoteEntity(
        title = title,
        body = "body for $title",
        tag = tag,
        createdAt = ts,
        updatedAt = ts,
    )

    @Test
    fun insert_then_byId_returns_inserted_row() = runBlocking {
        val db = freshDb("byid")
        try {
            val id = db.noteDao().insert(newNote("hello", 100L, tag = "t1"))
            val fetched = db.noteDao().byId(id)
            assertNotNull(fetched)
            assertEquals("hello", fetched!!.title)
            assertEquals("t1", fetched.tag)
            assertEquals(100L, fetched.createdAt)
        } finally {
            db.close()
        }
    }

    @Test
    fun observeAll_orders_by_updatedAt_desc() = runBlocking {
        val db = freshDb("order")
        try {
            db.noteDao().insert(newNote("oldest", 100L))
            db.noteDao().insert(newNote("middle", 200L))
            db.noteDao().insert(newNote("newest", 300L))
            val rows = db.noteDao().observeAll().first()
            assertEquals(listOf("newest", "middle", "oldest"), rows.map { it.title })
        } finally {
            db.close()
        }
    }

    @Test
    fun update_changes_persist() = runBlocking {
        val db = freshDb("update")
        try {
            val id = db.noteDao().insert(newNote("v1", 100L))
            val initial = db.noteDao().byId(id)!!
            db.noteDao().update(initial.copy(title = "v2", body = "edited", updatedAt = 200L))
            val updated = db.noteDao().byId(id)!!
            assertEquals("v2", updated.title)
            assertEquals("edited", updated.body)
            assertEquals(200L, updated.updatedAt)
            assertEquals(100L, updated.createdAt)
        } finally {
            db.close()
        }
    }

    @Test
    fun deleteById_removes_only_target_row() = runBlocking {
        val db = freshDb("delete")
        try {
            val keepId = db.noteDao().insert(newNote("keep", 100L))
            val killId = db.noteDao().insert(newNote("kill", 200L))
            db.noteDao().deleteById(killId)
            assertNull(db.noteDao().byId(killId))
            assertNotNull(db.noteDao().byId(keepId))
            assertEquals(1, db.noteDao().count())
        } finally {
            db.close()
        }
    }

    @Test
    fun deleteAll_empties_table() = runBlocking {
        val db = freshDb("deleteall")
        try {
            repeat(5) { db.noteDao().insert(newNote("n$it", 100L + it)) }
            assertEquals(5, db.noteDao().count())
            db.noteDao().deleteAll()
            assertEquals(0, db.noteDao().count())
            assertTrue(db.noteDao().observeAllOnce().isEmpty())
        } finally {
            db.close()
        }
    }
}
