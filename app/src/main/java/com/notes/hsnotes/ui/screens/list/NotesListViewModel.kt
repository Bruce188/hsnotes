package com.notes.hsnotes.ui.screens.list

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.notes.hsnotes.App
import com.notes.hsnotes.data.db.entity.NoteEntity
import com.notes.hsnotes.data.repo.NotesRepository
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * ViewModel for [NotesListScreen]. Streams the full notes list from
 * [NotesRepository] (which itself wraps Room's [Flow]). The repository is
 * read lazily via the [App.repository] accessor — only mounted post-unlock,
 * so this ViewModel cannot leak into a pre-unlock composition (MainActivity
 * gates the NavHost on [com.notes.hsnotes.ui.auth.LockState.Unlocked]).
 */
class NotesListViewModel(
    private val repository: NotesRepository,
) : ViewModel() {

    val notes: StateFlow<List<NoteEntity>> = repository.notes
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000L),
            initialValue = emptyList(),
        )

    /**
     * Delete the note with [id]. Caller is expected to drive any "undo"
     * affordance from the snackbar — this ViewModel does not retain a copy.
     */
    fun delete(id: Long) {
        viewModelScope.launch {
            repository.delete(id)
        }
    }

    companion object {
        /**
         * Production [ViewModelProvider.Factory]. Reads [App.repository] which
         * throws [com.notes.hsnotes.data.db.LockedException] pre-unlock. The
         * gate in MainActivity ensures this factory only runs once the DEK
         * is installed.
         */
        fun factory(app: App): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                return NotesListViewModel(repository = app.repository) as T
            }
        }
    }
}
