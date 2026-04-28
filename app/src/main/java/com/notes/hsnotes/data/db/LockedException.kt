package com.notes.hsnotes.data.db

/**
 * Thrown when a caller attempts to access [AppDatabase] (or the repository
 * built on top of it) before the user has unlocked with their passphrase.
 *
 * Phase 3 (SQLCipher under Room) wires this up; Phase 5 (AuthGate) ensures
 * UI never reaches a state where this can fire from a user perspective.
 *
 * Plan §3 — "lazy DB construction".
 */
class LockedException : IllegalStateException("Database is locked. Unlock with passphrase first.")
