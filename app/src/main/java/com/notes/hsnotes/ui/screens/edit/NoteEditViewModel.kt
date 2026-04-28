package com.notes.hsnotes.ui.screens.edit

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.notes.hsnotes.App
import com.notes.hsnotes.data.db.entity.NoteEntity
import com.notes.hsnotes.data.repo.NotesRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Editor state holder. New-note path constructs with `noteId = null`;
 * edit-existing path passes the row id and the VM hydrates from the repo.
 *
 * Field state is plain `String` (Compose's TextField only accepts String),
 * but the underlying note body is treated as user content — there is no
 * security-relevant material in this VM, so no CharArray hygiene is needed
 * here. Passphrases live behind [com.notes.hsnotes.ui.screens.settings.SettingsScreen]
 * which already enforces CharArray + DisposableEffect wipe.
 */
class NoteEditViewModel(
    private val repository: NotesRepository,
    private val noteId: Long?,
) : ViewModel() {

    private val _state = MutableStateFlow(UiState(isNew = noteId == null))
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        if (noteId != null) {
            viewModelScope.launch {
                val existing = repository.load(noteId)
                if (existing != null) {
                    _state.value = UiState(
                        id = existing.id,
                        title = existing.title,
                        body = existing.body,
                        tag = existing.tag.orEmpty(),
                        isNew = false,
                        loaded = true,
                    )
                } else {
                    // Row gone (concurrent delete from another flow). Surface
                    // an error sentinel; the screen routes back to list.
                    _state.update { it.copy(loaded = true, missing = true) }
                }
            }
        } else {
            _state.value = _state.value.copy(loaded = true)
        }
    }

    fun setTitle(value: String) {
        _state.update { it.copy(title = value) }
    }

    fun setBody(value: String) {
        _state.update { it.copy(body = value) }
    }

    fun setTag(value: String) {
        _state.update { it.copy(tag = value) }
    }

    /**
     * Persist current state. Skips save when both [UiState.title] and
     * [UiState.body] are blank — an empty new note is treated as a discard.
     * Returns `true` when something was written (or deleted), `false` on
     * the empty-discard branch so the screen can decide whether to surface
     * a toast.
     */
    fun save(onSaved: () -> Unit) {
        val s = _state.value
        if (s.isNew && s.title.isBlank() && s.body.isBlank()) {
            // Treat as discard — no row inserted.
            onSaved()
            return
        }
        viewModelScope.launch {
            repository.upsert(
                NoteEntity(
                    id = s.id,
                    title = s.title,
                    body = s.body,
                    tag = s.tag.takeIf { it.isNotBlank() },
                    // Repository owns timestamps — the placeholder values
                    // here are overwritten by NotesRepository.upsert.
                    createdAt = 0L,
                    updatedAt = 0L,
                )
            )
            onSaved()
        }
    }

    fun delete(onDeleted: () -> Unit) {
        val id = _state.value.id
        if (id == 0L) {
            onDeleted()
            return
        }
        viewModelScope.launch {
            repository.delete(id)
            onDeleted()
        }
    }

    data class UiState(
        val id: Long = 0L,
        val title: String = "",
        val body: String = "",
        val tag: String = "",
        val isNew: Boolean = true,
        val loaded: Boolean = false,
        val missing: Boolean = false,
    )

    companion object {
        fun factory(app: App, noteId: Long?): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return NoteEditViewModel(
                        repository = app.repository,
                        noteId = noteId,
                    ) as T
                }
            }
    }
}
