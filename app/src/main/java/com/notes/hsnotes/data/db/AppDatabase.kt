package com.notes.hsnotes.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.notes.hsnotes.data.db.entity.NoteEntity
import android.database.sqlite.SQLiteDatabaseLockedException
import net.zetetic.database.sqlcipher.SQLiteConnection
import net.zetetic.database.sqlcipher.SQLiteDatabaseHook
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

@Database(
    entities = [NoteEntity::class],
    version = 1,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {

    abstract fun noteDao(): NoteDao

    companion object {
        const val DB_NAME = "notes.db"

        init {
            // SQLCipher Android requires loading the native library before
            // any SupportOpenHelperFactory construction. Class-init runs
            // exactly once on first AppDatabase touch.
            System.loadLibrary("sqlcipher")
        }

        /**
         * Build the encrypted Room database with [dek] as the page-key.
         *
         * The supplied [dek] is copied into the SQLCipher factory; the factory
         * zeroes its copy after the first open (clearPassphrase = true). The
         * caller is still responsible for wiping its own [dek] reference.
         *
         * `fallbackToDestructiveMigration` is intentionally absent — losing
         * encrypted user data silently on schema mismatch defeats the entire
         * point of the retrofit. Future schema changes must add explicit
         * Room migrations.
         *
         * Plan §3 — SQLCipher under Room + lazy DB construction.
         */
        fun build(
            context: Context,
            dek: ByteArray,
            dbName: String = DB_NAME,
        ): AppDatabase {
            require(dek.size == 32) { "DEK must be 32 bytes (got ${dek.size})" }

            val hook = object : SQLiteDatabaseHook {
                override fun preKey(connection: SQLiteConnection) {
                    // No pre-key pragmas. Cipher defaults are fine for v1.
                }

                override fun postKey(connection: SQLiteConnection) {
                    // Plan §3 pragmas — must run after key application.
                    //  - cipher_memory_security: zero page buffers in mlocked memory
                    //    on unmap, blocks the "swap-out plaintext" forensic path.
                    //  - secure_delete: zero pages before reuse so freed rows leave
                    //    no recoverable residue inside the encrypted blob.
                    //  - journal_mode = MEMORY: prevents on-disk WAL/-journal files
                    //    that would otherwise leak plaintext page diffs (rollback
                    //    journal is encrypted, but MEMORY skips the disk write
                    //    entirely — matches the "no on-disk plaintext ever" rule).
                    //
                    // Pragma return-shape splits across these three:
                    //  - cipher_memory_security set-form returns NO rows. Bare
                    //    [execute] is correct. [executeForString] would throw
                    //    SQLiteDoneException ("no row to step") on this device.
                    //  - secure_delete + journal_mode set-forms DO return a row
                    //    (the new value). Bare [execute] rejects them with
                    //    "Queries can be performed using SQLiteDatabase query
                    //    or rawQuery methods only", so we step the row once
                    //    via [executeForString] and discard column 0.
                    //
                    // Pragma scope splits too: [cipher_memory_security] is
                    // per-connection (mlocked page buffers are connection-local
                    // memory, so every connection must opt in). [secure_delete]
                    // and [journal_mode] are database-scoped — once the primary
                    // (writable) connection sets them they stick for every
                    // subsequent reader. Room's SQLCipher pool opens a primary
                    // followed by N readers; the readers' postKey runs while
                    // the primary still holds the write lock for pool
                    // initialization, so attempting to re-set the db-scoped
                    // pragmas raises SQLiteDatabaseLockedException. Swallowing
                    // the lock exception is correct: the primary's earlier
                    // set is already in effect for the whole DB.
                    connection.execute("PRAGMA cipher_memory_security = ON;", emptyArray(), null)
                    try {
                        connection.executeForString("PRAGMA secure_delete = ON;", emptyArray(), null)
                    } catch (_: SQLiteDatabaseLockedException) {
                        // Primary already set it; readers inherit.
                    }
                    try {
                        connection.executeForString("PRAGMA journal_mode = MEMORY;", emptyArray(), null)
                    } catch (_: SQLiteDatabaseLockedException) {
                        // Primary already set it; readers inherit.
                    }
                }
            }

            // Pass a copy — clearPassphrase=true zeros the byte[] we hand in,
            // so we must not let SQLCipher mutate the caller's DEK array.
            val factory = SupportOpenHelperFactory(dek.copyOf(), hook, true)

            return Room
                .databaseBuilder(context.applicationContext, AppDatabase::class.java, dbName)
                .openHelperFactory(factory)
                .build()
        }
    }
}
