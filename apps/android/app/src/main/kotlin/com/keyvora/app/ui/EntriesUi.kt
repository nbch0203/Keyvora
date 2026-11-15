package com.keyvora.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.keyvora.app.AppContainer
import com.keyvora.app.core.CoreException
import com.keyvora.app.core.Entry
import com.keyvora.app.core.EntrySummary
import com.keyvora.app.sync.SyncCoordinator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

@Composable
fun MainNavigation() {
    val nav = rememberNavController()
    NavHost(nav, startDestination = "list") {
        composable("list") {
            EntryListScreen(
                onOpen = { nav.navigate("detail/$it") },
                onAdd = { nav.navigate("edit") },
                onSettings = { nav.navigate("settings") },
            )
        }
        composable("detail/{id}", arguments = listOf(navArgument("id") { type = NavType.StringType })) { back ->
            val id = back.arguments?.getString("id").orEmpty()
            EntryDetailScreen(
                id = id,
                onBack = { nav.popBackStack() },
                onEdit = { nav.navigate("edit?id=$id") },
                onConflicts = { nav.navigate("conflicts/$id") },
            )
        }
        composable("conflicts/{id}", arguments = listOf(navArgument("id") { type = NavType.StringType })) { back ->
            ConflictsScreen(back.arguments?.getString("id").orEmpty(), onBack = { nav.popBackStack() }, onGone = {
                nav.popBackStack("list", inclusive = false)
            })
        }
        composable(
            "edit?id={id}",
            arguments = listOf(navArgument("id") { type = NavType.StringType; nullable = true; defaultValue = null }),
        ) { back ->
            EntryEditScreen(back.arguments?.getString("id"), onDone = { nav.popBackStack() })
        }
        composable("settings") { SettingsScreen(onBack = { nav.popBackStack() }, onRestore = { nav.navigate("restore") }) }
        composable("restore") { RestoreScreen(onBack = { nav.popBackStack() }) }
    }
}

// ------------------------------------------------------------------------------------------------ list

class EntryListViewModel(private val c: AppContainer) : ViewModel() {
    val query = MutableStateFlow("")
    private val _entries = MutableStateFlow<List<EntrySummary>>(emptyList())
    val entries = _entries.asStateFlow()
    val sync = c.sync.ui
    private val _error = MutableStateFlow<String?>(null)
    val error = _error.asStateFlow()

    init {
        viewModelScope.launch {
            combine(c.vault.contentVersion, query) { _, q -> q }.collectLatest { q ->
                try {
                    _entries.value = c.vault.listEntries(q)
                    _error.value = null
                } catch (e: Exception) {
                    _error.value = e.errorCode()
                }
            }
        }
    }

    fun lock() = c.vault.lock()

    /** Re-runs sync; a pending KEYRING_CHANGED is detected again and the password dialog reappears. */
    fun retrySync() = c.sync.requestSync()

    fun clearRollbackWarning() {
        c.syncState.update { it.copy(rollbackWarning = false) }
        c.sync.refresh()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryListScreen(onOpen: (String) -> Unit, onAdd: () -> Unit, onSettings: () -> Unit) {
    val vm = appViewModel { EntryListViewModel(it) }
    val entries by vm.entries.collectAsStateWithLifecycle()
    val query by vm.query.collectAsStateWithLifecycle()
    val sync by vm.sync.collectAsStateWithLifecycle()
    val error by vm.error.collectAsStateWithLifecycle()
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Keyvora") },
                actions = {
                    IconButton(onClick = vm::lock) { Icon(Icons.Filled.Lock, contentDescription = "Bloquear") }
                    IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, contentDescription = "Ajustes") }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAdd) { Icon(Icons.Filled.Add, contentDescription = "Nueva entrada") }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            OutlinedTextField(
                value = query,
                onValueChange = { vm.query.value = it },
                label = { Text("Buscar") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            )
            SyncBanner(sync, vm::clearRollbackWarning, vm::retrySync)
            ErrorText(error)
            if (entries.isEmpty()) {
                Text(
                    if (query.isBlank()) "Tu bóveda está vacía. Pulsa + para añadir una cuenta." else "Sin resultados.",
                    modifier = Modifier.padding(16.dp),
                )
            }
            LazyColumn(Modifier.fillMaxSize()) {
                items(entries, key = { it.id }) { e ->
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .clickable { onOpen(e.id) }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(e.title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                            if (e.hasConflicts) Text("Conflicto", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelMedium)
                        }
                        if (e.username.isNotEmpty()) Text(e.username, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
                        e.urls.firstOrNull()?.let { Text(it, style = MaterialTheme.typography.bodySmall, maxLines = 1) }
                    }
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun SyncBanner(ui: SyncCoordinator.UiState, onDismissRollback: () -> Unit, onRetry: () -> Unit) {
    if (!ui.connected) return
    Column(Modifier.padding(horizontal = 16.dp)) {
        when {
            ui.running -> Text("Sincronizando…", style = MaterialTheme.typography.bodySmall)
            ui.state.lastError != null -> Text(errorMessage(ui.state.lastError), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            ui.state.dirty -> Text("Cambios pendientes de sincronizar.", style = MaterialTheme.typography.bodySmall)
        }
        if (ui.state.lastError == CoreException.KEYRING_CHANGED && !ui.running) {
            TextButton(onClick = onRetry) { Text("Introducir la contraseña maestra para seguir sincronizando") }
        }
        if (ui.lastResult?.keyringConflict == true) {
            Text("Se cambiaron las claves en dos dispositivos a la vez; puede que te pidan la contraseña una vez más.", style = MaterialTheme.typography.bodySmall)
        }
        if (ui.state.rollbackWarning) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Aviso: Google Drive devolvió una versión más antigua que una ya vista (posible restauración o manipulación). " +
                        "Se fusionó sin perder tus cambios locales.",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = onDismissRollback) { Text("Entendido") }
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------ detail

class EntryDetailViewModel(private val c: AppContainer, private val id: String) : ViewModel() {
    private val _entry = MutableStateFlow<Entry?>(null)
    val entry = _entry.asStateFlow()
    private val _error = MutableStateFlow<String?>(null)
    val error = _error.asStateFlow()
    private val _gone = MutableStateFlow(false)
    val gone = _gone.asStateFlow()

    init {
        viewModelScope.launch {
            c.vault.contentVersion.collectLatest { reload() }
        }
        // Drop the decrypted entry from memory when the vault locks.
        viewModelScope.launch {
            c.vault.status.collect { if (it != com.keyvora.app.vault.VaultManager.Status.UNLOCKED) _entry.value = null }
        }
    }

    private suspend fun reload() {
        try {
            _entry.value = c.vault.getEntry(id)
        } catch (e: CoreException) {
            if (e.code == CoreException.NOT_FOUND) _gone.value = true else _error.value = e.code
        }
    }

    fun copy(text: String) = c.clipboard.copy(text)

    fun delete() = viewModelScope.launch {
        try {
            c.vault.mutate { it.deleteEntry(id, c.vault.now()) }
            _gone.value = true
        } catch (e: Exception) {
            _error.value = e.errorCode()
        }
    }

    fun resolve(choice: Int) = viewModelScope.launch {
        try {
            c.vault.mutate { it.resolveConflict(id, choice, c.vault.now()) }
        } catch (e: Exception) {
            _error.value = e.errorCode()
        }
    }
}

@Composable
fun EntryDetailScreen(id: String, onBack: () -> Unit, onEdit: () -> Unit, onConflicts: () -> Unit) {
    val vm = appViewModel(key = "detail-$id") { EntryDetailViewModel(it, id) }
    val entry by vm.entry.collectAsStateWithLifecycle()
    val error by vm.error.collectAsStateWithLifecycle()
    val gone by vm.gone.collectAsStateWithLifecycle()
    var showPassword by rememberSaveable { mutableStateOf(false) }
    var showHistory by rememberSaveable { mutableStateOf(false) }
    var confirmDelete by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(gone) { if (gone) onBack() }
    val e = entry
    ScreenScaffold(
        e?.title ?: "Entrada",
        onBack = onBack,
        actions = {
            TextButton(onClick = onEdit, enabled = e != null) { Text("Editar") }
        },
    ) {
        ErrorText(error)
        if (e == null) return@ScreenScaffold
        if (e.conflicts.isNotEmpty()) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text("Hay ${e.conflicts.size} versión(es) en conflicto de otros dispositivos.", color = MaterialTheme.colorScheme.error)
                    TextButton(onClick = onConflicts) { Text("Revisar y resolver") }
                }
            }
        }
        LabeledValue("Usuario", e.username.ifEmpty { "—" }) {
            if (e.username.isNotEmpty()) TextButton(onClick = { vm.copy(e.username) }) { Text("Copiar") }
        }
        LabeledValue("Contraseña", if (showPassword) e.password else "••••••••••", monospace = showPassword) {
            TextButton(onClick = { showPassword = !showPassword }) { Text(if (showPassword) "Ocultar" else "Mostrar") }
            TextButton(onClick = { vm.copy(e.password) }) { Text("Copiar") }
        }
        if (e.urls.isNotEmpty()) LabeledValue("Sitios / apps", e.urls.joinToString("\n"))
        if (e.notes.isNotEmpty()) LabeledValue("Notas", e.notes)
        Text("Modificada: ${shortDate(e.updatedAt)} · Creada: ${shortDate(e.createdAt)}", style = MaterialTheme.typography.bodySmall)
        Text("Las copias se borran del portapapeles a los 30 s.", style = MaterialTheme.typography.bodySmall)
        if (e.passwordHistory.isNotEmpty()) {
            TextButton(onClick = { showHistory = !showHistory }) {
                Text(if (showHistory) "Ocultar historial" else "Historial de contraseñas (${e.passwordHistory.size})")
            }
            if (showHistory) {
                e.passwordHistory.forEach { h ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(h.password, fontFamily = FontFamily.Monospace)
                            Text("Retirada: ${shortDate(h.retiredAt)}", style = MaterialTheme.typography.bodySmall)
                        }
                        TextButton(onClick = { vm.copy(h.password) }) { Text("Copiar") }
                    }
                }
            }
        }
        OutlinedButton(onClick = { confirmDelete = true }, modifier = Modifier.fillMaxWidth()) {
            Text("Eliminar", color = MaterialTheme.colorScheme.error)
        }
    }
    if (confirmDelete && e != null) {
        ConfirmDialog(
            title = "¿Eliminar «${e.title}»?",
            text = "La entrada se eliminará en todos los dispositivos sincronizados.",
            confirm = "Eliminar",
            onConfirm = { confirmDelete = false; vm.delete() },
            onDismiss = { confirmDelete = false },
        )
    }
}

@Composable
private fun LabeledValue(label: String, value: String, monospace: Boolean = false, actions: @Composable () -> Unit = {}) {
    Column(Modifier.fillMaxWidth()) {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(value, modifier = Modifier.weight(1f), fontFamily = if (monospace) FontFamily.Monospace else null)
            actions()
        }
    }
}

// ------------------------------------------------------------------------------------------------ conflicts

@Composable
fun ConflictsScreen(id: String, onBack: () -> Unit, onGone: () -> Unit) {
    val vm = appViewModel(key = "detail-$id") { EntryDetailViewModel(it, id) }
    val entry by vm.entry.collectAsStateWithLifecycle()
    val gone by vm.gone.collectAsStateWithLifecycle()
    val error by vm.error.collectAsStateWithLifecycle()
    LaunchedEffect(gone) { if (gone) onGone() }
    val e = entry
    LaunchedEffect(e?.conflicts?.size) { if (e != null && e.conflicts.isEmpty()) onBack() }
    ScreenScaffold("Resolver conflictos", onBack = onBack) {
        ErrorText(error)
        if (e == null) return@ScreenScaffold
        Text("Se editó esta entrada en varios dispositivos a la vez. Nada se ha perdido: elige qué versión conservar.")
        VersionCard("Versión actual", e.title, e.username, e.password, e.urls, e.notes, "${shortDate(e.updatedAt)} · ${e.updatedBy}") {
            BusyButton("Conservar la versión actual", busy = false) { vm.resolve(-1) }
        }
        e.conflicts.forEachIndexed { i, cf ->
            if (cf.isDeletion) {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Otro dispositivo eliminó esta entrada", style = MaterialTheme.typography.titleSmall)
                        Text("${shortDate(cf.updatedAt)} · ${cf.updatedBy}", style = MaterialTheme.typography.bodySmall)
                        OutlinedButton(onClick = { vm.resolve(i) }, modifier = Modifier.fillMaxWidth()) { Text("Aceptar el borrado") }
                    }
                }
            } else {
                VersionCard("Versión en conflicto ${i + 1}", cf.title, cf.username, cf.password, cf.urls, cf.notes, "${shortDate(cf.updatedAt)} · ${cf.updatedBy}") {
                    OutlinedButton(onClick = { vm.resolve(i) }, modifier = Modifier.fillMaxWidth()) { Text("Usar esta versión") }
                }
            }
        }
    }
}

@Composable
private fun VersionCard(
    heading: String,
    title: String,
    username: String,
    password: String,
    urls: List<String>,
    notes: String,
    meta: String,
    action: @Composable () -> Unit,
) {
    var show by rememberSaveable(heading) { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(heading, style = MaterialTheme.typography.titleSmall)
            Text("Título: $title")
            Text("Usuario: ${username.ifEmpty { "—" }}")
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Contraseña: " + if (show) password else "••••••••", modifier = Modifier.weight(1f), fontFamily = if (show) FontFamily.Monospace else null)
                TextButton(onClick = { show = !show }) { Text(if (show) "Ocultar" else "Mostrar") }
            }
            if (urls.isNotEmpty()) Text("Sitios: ${urls.joinToString(", ")}")
            if (notes.isNotEmpty()) Text("Notas: $notes")
            Text(meta, style = MaterialTheme.typography.bodySmall)
            action()
        }
    }
}
