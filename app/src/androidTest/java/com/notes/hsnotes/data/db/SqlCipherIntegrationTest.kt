package com.notes.hsnotes.data.db

import androidx.test.platform.app.InstrumentationRegistry
import com.notes.hsnotes.data.db.entity.NoteEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File
import com.notes.hsnotes.App as AppClass

/**
 * SQLCipher under Room — integration coverage for Plan §3.1.
 *
 * On-device test: SQLCipher loads a JNI .so, so all six cases live in
 * androidTest/. Each test owns its own DB filename so reruns cannot leak
 * state across cases.
 */
class SqlCipherIntegrationTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private val correctDek: ByteArray = ByteArray(32) { 0x42.toByte() }
    private val wrongDek: ByteArray = ByteArray(32) { 0x77.toByte() }

    private val testDbs = mutableListOf<String>()

    @Before
    fun setUp() {
        testDbs.clear()
    }

    @After
    fun tearDown() {
        testDbs.forEach { name ->
            runCatching { context.deleteDatabase(name) }
        }
    }

    private fun freshDbName(tag: String): String {
        val name = "sqlcipher_${tag}_${System.nanoTime()}.db"
        testDbs += name
        // Ensure no leftover from a prior run.
        context.deleteDatabase(name)
        return name
    }

    private fun note(title: String, ts: Long) = NoteEntity(
        title = title,
        body = "body for $title",
        tag = null,
        createdAt = ts,
        updatedAt = ts,
    )

    // -------------------------------------------------------------------------
    // 1. Disk file is encrypted — first 16 bytes must NOT be the SQLite magic.
    // -------------------------------------------------------------------------
    @Test
    fun dbFile_first_16_bytes_are_not_sqlite_magic() {
        val name = freshDbName("magic")
        val db = AppDatabase.build(context, correctDek.copyOf(), name)
        // Force open + first write so the file lands on disk.
        runBlocking {
            db.noteDao().insert(note("seed", 1L))
        }
        db.close()

        val dbFile: File = context.getDatabasePath(name)
        assertTrue("DB file must exist after open", dbFile.exists())
        assertTrue("DB file must contain at least 16 bytes", dbFile.length() >= 16)

        val firstBytes = dbFile.inputStream().use { input ->
            ByteArray(16).also { buf ->
                var read = 0
                while (read < 16) {
                    val n = input.read(buf, read, 16 - read)
                    if (n <= 0) break
                    read += n
                }
            }
        }
        // SQLite plaintext header.
        val sqliteMagic = "SQLite format 3 ".toByteArray(Charsets.US_ASCII)
        assertFalse(
            "DB header looks like a plaintext SQLite file — encryption did not apply",
            firstBytes.contentEquals(sqliteMagic),
        )
    }

    // -------------------------------------------------------------------------
    // 2. Round-trip via DAO with the correct DEK.
    // -------------------------------------------------------------------------
    @Test
    fun dao_roundtrip_with_correct_dek_succeeds() {
        val name = freshDbName("roundtrip")
        val db = AppDatabase.build(context, correctDek.copyOf(), name)
        try {
            runBlocking {
                val id = db.noteDao().insert(note("Coffee", 5_000L))
                val fetched = db.noteDao().byId(id)
                assertNotNull("inserted row must be readable", fetched)
                assertEquals("Coffee", fetched!!.title)
                assertEquals("body for Coffee", fetched.body)
            }
        } finally {
            db.close()
        }
    }

    // -------------------------------------------------------------------------
    // 3. Wrong DEK must NOT open the database.
    // -------------------------------------------------------------------------
    @Test
    fun opening_db_with_wrong_dek_throws_SQLiteException() {
        val name = freshDbName("wrongdek")
        // First open with the correct DEK so the file exists + is keyed.
        val correctDb = AppDatabase.build(context, correctDek.copyOf(), name)
        runBlocking { correctDb.noteDao().insert(note("seed", 1L)) }
        correctDb.close()

        // Now try to open the same file with a different DEK.
        val wrongDb = AppDatabase.build(context, wrongDek.copyOf(), name)
        var caught: Throwable? = null
        try {
            runBlocking { wrongDb.noteDao().byId(1L) }
            fail("expected SQLite open to fail with wrong DEK")
        } catch (t: Throwable) {
            caught = t
        } finally {
            runCatching { wrongDb.close() }
        }
        assertNotNull("wrong DEK must throw", caught)
        // SQLCipher's signal: "file is not a database" — surfaces as
        // SQLiteException (or a wrapping Room/Exec exception). Walk the cause
        // chain since Room may wrap in its own runtime exception.
        val chain = generateSequence(caught) { it.cause }.toList()
        val matched = chain.any { ex ->
            val msg = ex.message.orEmpty()
            msg.contains("not a database", ignoreCase = true) ||
                msg.contains("file is encrypted", ignoreCase = true) ||
                msg.contains("encrypt", ignoreCase = true)
        }
        assertTrue(
            "exception chain must mention encryption/db-format failure (got: ${chain.map { it::class.simpleName + ":" + it.message }})",
            matched,
        )
    }

    // -------------------------------------------------------------------------
    // 4. App.database / App.repository must throw LockedException pre-unlock.
    // -------------------------------------------------------------------------
    @Test
    fun locked_db_accessor_throws_LockedException_pre_unlock() {
        val app = context.applicationContext as AppClass
        // Force a clean locked state in case a prior test installed something.
        app.closeAndZeroizeDatabase()

        try {
            app.database
            fail("expected LockedException accessing app.database pre-install")
        } catch (e: LockedException) {
            // expected
        }
        try {
            app.repository
            fail("expected LockedException accessing app.repository pre-install")
        } catch (e: LockedException) {
            // expected
        }

        // After install, both must be reachable.
        app.installDatabase(correctDek.copyOf())
        try {
            assertNotNull("database must be reachable post-install", app.database)
            assertNotNull("repository must be reachable post-install", app.repository)
        } finally {
            app.closeAndZeroizeDatabase()
        }
        // After close, locked again.
        try {
            app.database
            fail("expected LockedException accessing app.database post-close")
        } catch (e: LockedException) {
            // expected
        }
    }

    // -------------------------------------------------------------------------
    // 5. PRAGMA journal_mode must be MEMORY after open (no on-disk WAL).
    // -------------------------------------------------------------------------
    @Test
    fun pragma_journal_mode_is_MEMORY_after_open() {
        val name = freshDbName("journal")
        val db = AppDatabase.build(context, correctDek.copyOf(), name)
        try {
            // Force open.
            runBlocking { db.noteDao().insert(note("seed", 1L)) }
            val mode = db.openHelper.readableDatabase
                .query("PRAGMA journal_mode;")
                .use { c ->
                    assertTrue(c.moveToFirst())
                    c.getString(0)
                }
            assertEquals("memory", mode.lowercase())
        } finally {
            db.close()
        }
    }

    // -------------------------------------------------------------------------
    // 6. PRAGMA secure_delete must report ON (=1) after open.
    // -------------------------------------------------------------------------
    @Test
    fun pragma_secure_delete_is_ON_after_open() {
        val name = freshDbName("securedel")
        val db = AppDatabase.build(context, correctDek.copyOf(), name)
        try {
            runBlocking { db.noteDao().insert(note("seed", 1L)) }
            val flag = db.openHelper.readableDatabase
                .query("PRAGMA secure_delete;")
                .use { c ->
                    assertTrue(c.moveToFirst())
                    c.getInt(0)
                }
            assertEquals(1, flag)
        } finally {
            db.close()
        }
    }
}
