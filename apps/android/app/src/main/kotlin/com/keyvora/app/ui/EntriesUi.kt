package com.keyvora.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.text.font.FontWeight
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

    /** Copies an entry's password (cleared from the clipboard after 30 s). */
    suspend fun copyPassword(id: String): Boolean = try {
        c.clipboard.copy(c.vault.getEntry(id).password)
        true
    } catch (_: Exception) {
        false
    }

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
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        BrandMark(34.dp)
                        Spacer(Modifier.width(12.dp))
                        Text("Keyvora", fontWeight = FontWeight.SemiBold)
                    }
                },
                actions = {
                    IconButton(onClick = vm::lock) { Icon(Icons.Filled.Lock, contentDescription = "Bloquear") }
                    IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, contentDescription = "Ajustes") }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface),
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onAdd,
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text("Nueva entrada") },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            OutlinedTextField(
                value = query,
                onValueChange = { vm.query.value = it },
                placeholder = { Text("Buscar en tu bóveda") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { vm.query.value = "" }) { Icon(Icons.Filled.Clear, contentDescription = "Borrar búsqueda") }
                    }
                },
                singleLine = true,
                shape = RoundedCornerShape(28.dp),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            )
            Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SyncBanner(sync, vm::clearRollbackWarning, vm::retrySync)
                ErrorText(error)
            }
            if (entries.isEmpty()) {
                EmptyState(query.isBlank())
            } else {
                Text(
                    if (entries.size == 1) "1 entrada" else "${entries.size} entradas",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 24.dp, top = 8.dp, bottom = 4.dp),
                )
            }
            LazyColumn(
                Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = 12.dp, end = 12.dp, bottom = 96.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                items(entries, key = { it.id }) { e ->
                    EntryRow(e, onOpen = { onOpen(e.id) }) {
                        scope.launch {
                            val ok = vm.copyPassword(e.id)
                            snackbar.showSnackbar(if (ok) "Contraseña copiada. Se borrará en 30 s." else "No se pudo copiar.")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EntryRow(e: EntrySummary, onOpen: () -> Unit, onCopy: () -> Unit) {
    Card(
        onClick = onOpen,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Monogram(e.title)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        e.title,
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (e.hasConflicts) {
                        Spacer(Modifier.width(8.dp))
                        Text("Conflicto", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelMedium)
                    }
                }
                val sub = listOfNotNull(e.username.takeIf { it.isNotEmpty() }, e.urls.firstOrNull()?.let(::displayHostOf)).joinToString(" · ")
                if (sub.isNotEmpty()) {
                    Text(
                        sub,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            IconButton(onClick = onCopy) { Icon(KvIcons.Copy, contentDescription = "Copiar contraseña de ${e.title}") }
        }
    }
}

@Composable
private fun EmptyState(emptyVault: Boolean) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 32.dp, vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Icon(
            if (emptyVault) KvIcons.Shield else Icons.Filled.Search,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.outline,
            modifier = Modifier.size(56.dp),
        )
        Text(if (emptyVault) "Tu bóveda está vacía" else "Sin resultados", style = MaterialTheme.typography.titleMedium)
        Text(
            if (emptyVault) "Pulsa «Nueva entrada» para guardar tu primera cuenta." else "Prueba con otro título, usuario o web.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun SyncBanner(ui: SyncCoordinator.UiState, onDismissRollback: () -> Unit, onRetry: () -> Unit) {
    if (!ui.connected) return
    when {
        ui.running -> Text("Sincronizando con Google Drive…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        ui.state.lastError != null -> Notice(errorMessage(ui.state.lastError), NoticeKind.ERROR) {
            if (ui.state.lastError == CoreException.KEYRING_CHANGED) {
                TextButton(onClick = onRetry) { Text("Introducir la contraseña maestra") }
            }
        }
        ui.state.dirty -> Text("Cambios pendientes de sincronizar.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    if (ui.lastResult?.keyringConflict == true) {
        Notice("Se cambiaron las claves en dos dispositivos a la vez; puede que te pidan la contraseña una vez más.")
    }
    if (ui.state.rollbackWarning) {
        Notice(
            "Google Drive devolvió una versión más antigua que una ya vista (posible restauración o manipulación). " +
                "Se fusionó sin perder tus cambios locales.",
            NoticeKind.WARNING,
        ) { TextButton(onClick = onDismissRollback) { Text("Entendido") } }
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
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    fun copy(what: String, text: String) {
        vm.copy(text)
        scope.launch { snackbar.showSnackbar("$what copiado. Se borrará en 30 s.") }
    }
    LaunchedEffect(gone) { if (gone) onBack() }
    val e = entry
    ScreenScaffold(
        "",
        onBack = onBack,
        actions = {
            IconButton(onClick = onEdit, enabled = e != null) { Icon(Icons.Filled.Edit, contentDescription = "Editar") }
            IconButton(onClick = { confirmDelete = true }, enabled = e != null) { Icon(Icons.Filled.Delete, contentDescription = "Eliminar") }
        },
        snackbar = snackbar,
    ) {
        ErrorText(error)
        if (e == null) return@ScreenScaffold
        Row(verticalAlignment = Alignment.CenterVertically) {
            Monogram(e.title, 60.dp)
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(e.title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                e.urls.firstOrNull()?.let {
                    Text(displayHostOf(it), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        if (e.conflicts.isNotEmpty()) {
            Notice("Hay ${e.conflicts.size} versión(es) en conflicto de otros dispositivos.", NoticeKind.ERROR) {
                TextButton(onClick = onConflicts) { Text("Revisar y resolver") }
            }
        }
        SectionCard {
            DetailField(Icons.Filled.Person, "Usuario", e.username.ifEmpty { "—" }) {
                if (e.username.isNotEmpty()) {
                    IconButton(onClick = { copy("Usuario", e.username) }) { Icon(KvIcons.Copy, contentDescription = "Copiar usuario") }
                }
            }
            DetailField(KvIcons.Key, "Contraseña", if (showPassword) e.password else "••••••••••••", monospace = showPassword) {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(if (showPassword) KvIcons.VisibilityOff else KvIcons.Visibility, contentDescription = if (showPassword) "Ocultar" else "Mostrar")
                }
                IconButton(onClick = { copy("Contraseña", e.password) }) { Icon(KvIcons.Copy, contentDescription = "Copiar contraseña") }
            }
            if (e.urls.isNotEmpty()) DetailField(KvIcons.Link, "Sitios web o apps", e.urls.joinToString("\n"))
            if (e.notes.isNotEmpty()) DetailField(KvIcons.Notes, "Notas", e.notes)
        }
        if (e.passwordHistory.isNotEmpty()) {
            SectionCard {
                SettingsRow(
                    KvIcons.History,
                    "Historial de contraseñas",
                    "${e.passwordHistory.size} anterior(es)",
                    trailing = { Text(if (showHistory) "Ocultar" else "Ver", color = MaterialTheme.colorScheme.primary) },
                ) { showHistory = !showHistory }
                if (showHistory) {
                    e.passwordHistory.forEach { h ->
                        Row(Modifier.padding(start = 60.dp, end = 8.dp, bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(h.password, fontFamily = FontFamily.Monospace)
                                Text("Retirada: ${shortDate(h.retiredAt)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            IconButton(onClick = { copy("Contraseña anterior", h.password) }) { Icon(KvIcons.Copy, contentDescription = "Copiar") }
                        }
                    }
                }
            }
        }
        Text(
            "Modificada: ${shortDate(e.updatedAt)} · Creada: ${shortDate(e.createdAt)}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
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
private fun DetailField(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    value: String,
    monospace: Boolean = false,
    actions: @Composable () -> Unit = {},
) {
    Row(Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(18.dp))
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyLarge, fontFamily = if (monospace) FontFamily.Monospace else null)
        }
        actions()
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
