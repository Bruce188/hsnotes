package com.notes.hsnotes

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.notes.hsnotes.ui.auth.AuthGateScreen
import com.notes.hsnotes.ui.auth.AuthViewModel
import com.notes.hsnotes.ui.auth.LockState
import com.notes.hsnotes.ui.auth.SetupScreen
import com.notes.hsnotes.ui.migration.MigrationWizardScreen
import com.notes.hsnotes.ui.nav.Routes
import com.notes.hsnotes.ui.screens.edit.NoteEditScreen
import com.notes.hsnotes.ui.screens.list.NotesListScreen
import com.notes.hsnotes.ui.screens.settings.SettingsScreen
import com.notes.hsnotes.ui.theme.HSNotesTheme

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Plan §5.4 — FLAG_SECURE blocks screenshots, screen recordings, and
        // the recents-overview thumbnail across the whole activity. Set BEFORE
        // setContent so the very first frame is already protected.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val app = application as App
        setContent {
            HSNotesTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val vm: AuthViewModel = viewModel(factory = AuthViewModel.factory(app))
                    val state by vm.state.collectAsState()

                    // State-driven gate. The NavHost (Unlocked branch) is
                    // never composed pre-unlock, so [App.repository] /
                    // [App.database] cannot be touched before the DEK lands.
                    when (state) {
                        LockState.Setup -> SetupScreen(vm = vm, onComplete = {})
                        LockState.Wiped -> SetupScreen(vm = vm, onComplete = {})
                        is LockState.Locked -> AuthGateScreen(vm = vm)
                        LockState.Unlocking -> AuthGateScreen(vm = vm)
                        // Review V-N1 — render same UI as Unlocking so a coercer
                        // sees a normal unlock animation; the post-unlock
                        // NavHost is NOT mounted because no DEK was unwrapped.
                        LockState.PanicSpinner -> AuthGateScreen(vm = vm)
                        is LockState.Migrating -> MigrationWizardScreen(
                            state = state as LockState.Migrating,
                            onDismissError = { vm.dismissMigrationError() },
                        )
                        LockState.Unlocked -> {
                            val nav = rememberNavController()
                            NavHost(navController = nav, startDestination = Routes.LIST) {
                                composable(Routes.LIST) {
                                    NotesListScreen(
                                        onNew = { nav.navigate(Routes.NEW) },
                                        onEdit = { id -> nav.navigate(Routes.edit(id)) },
                                        onSettings = { nav.navigate(Routes.SETTINGS) }
                                    )
                                }
                                composable(Routes.NEW) {
                                    NoteEditScreen(noteId = null, onDone = { nav.popBackStack() })
                                }
                                composable(
                                    route = Routes.EDIT,
                                    arguments = listOf(navArgument("id") { type = NavType.LongType })
                                ) { entry ->
                                    val id = entry.arguments?.getLong("id")
                                    NoteEditScreen(noteId = id, onDone = { nav.popBackStack() })
                                }
                                composable(Routes.SETTINGS) {
                                    SettingsScreen(onBack = { nav.popBackStack() })
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
