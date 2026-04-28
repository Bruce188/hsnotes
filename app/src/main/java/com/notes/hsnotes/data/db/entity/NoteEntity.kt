package com.notes.hsnotes.data.db.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * A single user note.
 *
 * - [id] — autogen primary key
 * - [title] — short heading; may be blank (UI shows "(untitled)")
 * - [body] — long-form text; may be blank
 * - [tag] — optional category tag (free-form string), null when unset
 * - [createdAt] — epoch millis at first save
 * - [updatedAt] — epoch millis at most recent save; equals [createdAt] on insert
 */
@Entity(tableName = "notes")
data class NoteEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val title: String,
    val body: String,
    val tag: String? = null,
    val createdAt: Long,
    val updatedAt: Long,
)
