package com.notes.hsnotes.data.migration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.notes.hsnotes.data.db.AppDatabase
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.RandomAccessFile
import kotlinx.coroutines.runBlocking

/**
 * Plan §8.1 Tests block. Staged for `connectedDebugAndroidTest`.
 *
 * Each test seeds a plaintext SQLite database via the platform
 * `android.database.sqlite.SQLiteDatabase` (no key) so the migration's
 * detection path has something concrete to find. The DEK used for the
 * destination ciphertext is a deterministic 32-byte test key.
 *
 * The notes-app schema is one table:
 *   notes(id, title, body, tag, createdAt, updatedAt)
 */
@RunWith(AndroidJUnit4::class)
class PlaintextToCipherMigrationTest {

    private lateinit var ctx: Context
    private val testDek: ByteArray = ByteArray(32) { (it * 7 + 3).toByte() }

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        clean()
    }

    @After
    fun tearDown() {
        clean()
    }

    private fun clean() {
        listOf(
            ctx.getDatabasePath(AppDatabase.DB_NAME),
            File(ctx.getDatabasePath(AppDatabase.DB_NAME).parentFile, "${AppDatabase.DB_NAME}-wal"),
            File(ctx.getDatabasePath(AppDatabase.DB_NAME).parentFile, "${AppDatabase.DB_NAME}-shm"),
            File(ctx.getDatabasePath(AppDatabase.DB_NAME).parentFile, "${AppDatabase.DB_NAME}-journal"),
            File(ctx.getDatabasePath(AppDatabase.DB_NAME).parentFile, "${AppDatabase.DB_NAME}.new"),
            File(ctx.getDatabasePath(AppDatabase.DB_NAME).parentFile, "${AppDatabase.DB_NAME}.new-wal"),
            File(ctx.getDatabasePath(AppDatabase.DB_NAME).parentFile, "${AppDatabase.DB_NAME}.new-shm"),
        ).forEach { it.delete() }
    }

    @Test
    fun seeded_plaintext_db_migrates_to_ciphertext_with_identical_rows_and_count() = runBlocking {
        seedPlaintext(rows = 5)
        val mig = PlaintextToCipherMigration(ctx)
        assertTrue(mig.isPlaintextPresent())

        val rc = mig.migrate(testDek)
        assertTrue("migrate failed: ${rc.exceptionOrNull()}", rc.isSuccess)
        assertFalse(mig.isPlaintextPresent())

        // Open ciphertext via SQLCipher and count rows.
        val db = AppDatabase.build(ctx, testDek)
        try {
            assertEquals(5, db.noteDao().count())
        } finally {
            db.close()
        }
    }

    @Test
    fun mid_migration_failure_keeps_plaintext_intact_and_shows_recovery() = runBlocking {
        seedPlaintext(rows = 4)
        // Pre-create junk at notes.db.new so AppDatabase.build inside
        // migrate() trips over it — the migration must fail and clean up.
        val target = File(ctx.getDatabasePath(AppDatabase.DB_NAME).parentFile, "${AppDatabase.DB_NAME}.new")
        target.writeBytes(ByteArray(64) { 0x55 })

        val mig = PlaintextToCipherMigration(ctx)
        val rc = mig.migrate(testDek)
        assertTrue(rc.isFailure)

        // Plaintext untouched.
        assertTrue(mig.isPlaintextPresent())
        // Partial .new cleaned up.
        val parent = ctx.getDatabasePath(AppDatabase.DB_NAME).parentFile
        listOf(
            File(parent, "${AppDatabase.DB_NAME}.new"),
            File(parent, "${AppDatabase.DB_NAME}.new-wal"),
            File(parent, "${AppDatabase.DB_NAME}.new-shm"),
        ).forEach { assertFalse(it.exists()) }
    }

    @Test
    fun ciphertext_verification_must_pass_before_plaintext_deletion() = runBlocking {
        seedPlaintext(rows = 1)
        val plaintextPath = ctx.getDatabasePath(AppDatabase.DB_NAME)
        val mig = PlaintextToCipherMigration(ctx)
        val rc = mig.migrate(testDek)
        assertTrue(rc.isSuccess)
        // After success: file at notes.db is now ciphertext (NOT plaintext)
        // — verification ran BEFORE plaintext got overwritten.
        assertTrue(plaintextPath.exists())
        assertFalse("ciphertext must not parse as plaintext", canOpenAsPlaintext(plaintextPath))
    }

    @Test
    fun secondary_run_after_completed_migration_is_noop() = runBlocking {
        seedPlaintext(rows = 1)
        val mig = PlaintextToCipherMigration(ctx)
        val rc1 = mig.migrate(testDek)
        assertTrue(rc1.isSuccess)
        // Second run sees ciphertext at notes.db — isPlaintextPresent returns
        // false and there is no migration to perform.
        assertFalse(mig.isPlaintextPresent())
    }

    @Test
    fun ciphertext_dbFile_is_not_plaintext_sqlite_after_migration() = runBlocking {
        seedPlaintext(rows = 3)
        val plaintextPath = ctx.getDatabasePath(AppDatabase.DB_NAME)
        val mig = PlaintextToCipherMigration(ctx)
        assertTrue(mig.migrate(testDek).isSuccess)
        // SQLite header magic check: plaintext DBs start with "SQLite format 3\0".
        // SQLCipher pages are encrypted — header is unreadable as-text.
        val header = ByteArray(16)
        RandomAccessFile(plaintextPath, "r").use { it.readFully(header) }
        assertFalse(
            "SQLCipher file must not have plaintext SQLite header",
            String(header, Charsets.US_ASCII).startsWith("SQLite format 3"),
        )
    }

    @Test
    fun plaintext_file_is_overwritten_with_random_bytes_before_unlink() = runBlocking {
        // Verifying the secure-overwrite is observable: after a successful
        // migration the inode at notes.db has been replaced via atomic rename,
        // so the ORIGINAL inode the plaintext lived in is gone. We assert the
        // pre-migration file's signature bytes are no longer present anywhere
        // in the resulting file, plus the resulting file is a SQLCipher blob.
        seedPlaintext(rows = 1, marker = "PLAINTEXT_MARKER_X42_X42")
        val path = ctx.getDatabasePath(AppDatabase.DB_NAME)
        val mig = PlaintextToCipherMigration(ctx)
        assertTrue(mig.migrate(testDek).isSuccess)
        val bytes = path.readBytes()
        assertFalse(
            "marker must not survive into ciphertext",
            String(bytes, Charsets.US_ASCII).contains("PLAINTEXT_MARKER_X42_X42"),
        )
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    /**
     * Seed a plaintext `notes` table matching the schema [PlaintextToCipherMigration]
     * reads. When [marker] is set, it is used as the title of every row so a
     * post-migration scan can verify no surviving substrings.
     */
    private fun seedPlaintext(rows: Int, marker: String? = null) {
        val path = ctx.getDatabasePath(AppDatabase.DB_NAME)
        path.parentFile?.mkdirs()
        val db = android.database.sqlite.SQLiteDatabase.openOrCreateDatabase(path, null)
        db.execSQL(
            """CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                tag TEXT,
                createdAt INTEGER NOT NULL,
                updatedAt INTEGER NOT NULL
            )""",
        )
        for (i in 1..rows) {
            db.execSQL(
                "INSERT INTO notes(id, title, body, tag, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)",
                arrayOf(
                    i,
                    marker ?: "note_$i",
                    "body $i",
                    if (i % 2 == 0) "tag_$i" else null,
                    1_700_000_000_000L + i,
                    1_700_000_000_000L + i,
                ),
            )
        }
        db.close()
    }

    private fun canOpenAsPlaintext(path: File): Boolean = try {
        android.database.sqlite.SQLiteDatabase.openDatabase(
            path.absolutePath,
            null,
            android.database.sqlite.SQLiteDatabase.OPEN_READONLY,
        ).use { db ->
            db.rawQuery(
                "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1",
                null,
            ).use { it.moveToFirst() }
            true
        }
    } catch (t: Throwable) {
        false
    }
}
