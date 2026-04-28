package com.notes.hsnotes.ui.nav

object Routes {
    const val LIST = "notes"
    const val NEW = "notes/new"
    const val EDIT = "notes/edit/{id}"
    fun edit(id: Long) = "notes/edit/$id"
    const val SETTINGS = "settings"
}
