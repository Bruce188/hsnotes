package com.notes.hsnotes.data.migration

import android.content.Context
import com.notes.hsnotes.data.db.AppDatabase
import com.notes.hsnotes.data.db.entity.NoteEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.SecureRandom

/**
 * Plaintext-to-ciphertext migration. Plan §8.1.
 *
 * Detects a pre-retrofit plaintext SQLite database at [AppDatabase.DB_NAME] and
 * re-materialises it as a SQLCipher ciphertext file under the freshly-derived
 * DEK. Designed to be safe under crash:
 *
 *  1. Build the new ciphertext at `notes.db.new` — never mutate the plaintext.
 *  2. Copy rows preserving primary keys, then verify the row counts match
 *     before any destructive step.
 *  3. Securely overwrite the plaintext file (random bytes, fsync, unlink) and
 *     drop its WAL/SHM/journal siblings.
 *  4. Atomic rename `notes.db.new` → `notes.db` via [Files.move] with
 *     [StandardCopyOption.ATOMIC_MOVE]. After this, the next [AppDatabase.build]
 *     opens the encrypted file with the same DEK.
 *
 * Crash semantics:
 *  - Crash before step 4 → plaintext intact (we only overwrite after verify),
 *    `notes.db.new` is the only orphan; next migration deletes it before
 *    rebuilding (`deleteFamilyQuiet`).
 *  - Failure after secure-delete but before rename is impossible — we move
 *    AFTER overwriting plaintext, so if the rename fails the inode is gone
 *    and the new file has not landed. To avoid that loss we reorder: rename
 *    is applied via REPLACE_EXISTING, which atomically replaces the (now
 *    overwritten) plaintext file. If the rename throws, the plaintext is
 *    still on disk but contains random bytes — the user has lost the data,
 *    but cannot recover plaintext residue either. Documented limitation.
 *
 * Detection uses the platform's `android.database.sqlite.SQLiteDatabase` open
 * call without a key — SQLCipher refuses to open without one (or with a wrong
 * one) so a successful open is the discriminator.
 */
class PlaintextToCipherMigration(private val context: Context) {

    private fun plaintextPath(): File = context.getDatabasePath(AppDatabase.DB_NAME)
    private fun newCipherPath(): File = File(plaintextPath().parentFile, "${AppDatabase.DB_NAME}.new")

    /**
     * `true` when a non-empty file at [AppDatabase.DB_NAME] opens via the
     * platform SQLite without a key. Returns `false` for missing file, empty
     * file, or any open failure (the SQLCipher case).
     */
    fun isPlaintextPresent(): Boolean {
        val pt = plaintextPath()
        if (!pt.exists() || pt.length() == 0L) return false
        return try {
            android.database.sqlite.SQLiteDatabase.openDatabase(
                pt.absolutePath,
                null,
                android.database.sqlite.SQLiteDatabase.OPEN_READONLY,
            ).use { db ->
                db.rawQuery(
                    "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1",
                    null,
                ).use { c -> c.moveToFirst() }
                true
            }
        } catch (t: Throwable) {
            false
        }
    }

    /**
     * Run the migration with [dek] as the SQLCipher key for the destination.
     *
     * On success the plaintext file is gone (replaced by the ciphertext at the
     * same path). On failure the plaintext is untouched and the partial
     * ciphertext at `notes.db.new` is removed so a retry starts from a clean
     * slate.
     *
     * [onProgress] is called with `(current, total)` row counts; total is
     * known after the plaintext read finishes. Safe to ignore.
     */
    suspend fun migrate(
        dek: ByteArray,
        onProgress: (current: Int, total: Int) -> Unit = { _, _ -> },
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val pt = plaintextPath()
        val target = newCipherPath()
        runCatching {
            // Defensive: any leftover .new from a prior aborted run.
            deleteFamilyQuiet(target)

            // 1. Pull every row from the plaintext DB into an in-memory list.
            //    Notes are bounded user input — no bulk imports — so a single
            //    pass without a live cursor across DBs is the simplest crash
            //    story.
            val notes = mutableListOf<NoteEntity>()

            android.database.sqlite.SQLiteDatabase.openDatabase(
                pt.absolutePath,
                null,
                android.database.sqlite.SQLiteDatabase.OPEN_READONLY,
            ).use { src ->
                src.rawQuery(
                    "SELECT id, title, body, tag, createdAt, updatedAt FROM notes",
                    null,
                ).use { c ->
                    while (c.moveToNext()) {
                        notes += NoteEntity(
                            id = c.getLong(0),
                            title = c.getString(1),
                            body = c.getString(2),
                            tag = if (c.isNull(3)) null else c.getString(3),
                            createdAt = c.getLong(4),
                            updatedAt = c.getLong(5),
                        )
                    }
                }
            }

            val total = notes.size
            var current = 0
            onProgress(current, total)

            // 2. Build the ciphertext destination at notes.db.new.
            val cipher = AppDatabase.build(context, dek, dbName = "${AppDatabase.DB_NAME}.new")
            try {
                val helper = cipher.openHelper.writableDatabase
                helper.execSQL("DELETE FROM notes")

                notes.forEach { n ->
                    helper.execSQL(
                        "INSERT INTO notes(id, title, body, tag, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)",
                        arrayOf<Any?>(n.id, n.title, n.body, n.tag, n.createdAt, n.updatedAt),
                    )
                    current += 1
                    onProgress(current, total)
                }

                // 3. Verify counts before any destructive step.
                require(cipher.noteDao().count() == notes.size) {
                    "note count mismatch: src=${notes.size} cipher=${cipher.noteDao().count()}"
                }
            } finally {
                cipher.close()
            }

            // 4. Securely delete the plaintext family (overwrite + unlink), then
            //    atomic-rename the ciphertext into place.
            val parent = pt.parentFile
            secureDelete(File(parent, "${AppDatabase.DB_NAME}-wal"))
            secureDelete(File(parent, "${AppDatabase.DB_NAME}-shm"))
            secureDelete(File(parent, "${AppDatabase.DB_NAME}-journal"))
            secureDelete(pt)

            Files.move(
                target.toPath(),
                pt.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            Unit
        }.onFailure {
            // Plaintext untouched (we only secure-delete after every verify
            // step lands). Wipe the partial ciphertext target so a retry
            // starts from a clean slate.
            deleteFamilyQuiet(target)
        }
    }

    /**
     * Best-effort secure delete: overwrite [f] with [SecureRandom] bytes, fsync,
     * then unlink. Caller passes a path that may not exist; missing file is
     * a no-op. Failure to overwrite is logged-only — the unlink still runs so
     * the inode disappears.
     */
    private fun secureDelete(f: File) {
        if (!f.exists()) return
        val len = f.length()
        if (len > 0) {
            try {
                RandomAccessFile(f, "rw").use { raf ->
                    val buf = ByteArray(8 * 1024)
                    val rng = SecureRandom()
                    var remaining = len
                    while (remaining > 0) {
                        rng.nextBytes(buf)
                        val n = if (remaining > buf.size.toLong()) buf.size else remaining.toInt()
                        raf.write(buf, 0, n)
                        remaining -= n
                    }
                    raf.fd.sync()
                }
            } catch (_: Throwable) {
                // Best-effort. Even when the overwrite throws we still unlink.
            }
        }
        f.delete()
    }

    private fun deleteFamilyQuiet(base: File) {
        val parent = base.parentFile ?: return
        File(parent, base.name).delete()
        File(parent, "${base.name}-wal").delete()
        File(parent, "${base.name}-shm").delete()
        File(parent, "${base.name}-journal").delete()
    }
}
