package com.keyvora.app.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.TextButton
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.keyvora.app.AppContainer
import com.keyvora.app.core.EntryInput
import com.keyvora.app.core.GeneratorOptions
import com.keyvora.app.vault.VaultManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

class EntryEditViewModel(private val c: AppContainer, private val id: String?) : ViewModel() {
    data class Form(
        val title: String = "",
        val username: String = "",
        val password: String = "",
        val urls: String = "",
        val notes: String = "",
    ) {
        override fun toString() = "Form(<redacted>)"
    }

    data class State(
        val loaded: Boolean = false,
        val busy: Boolean = false,
        val error: String? = null,
        val errorDetail: String? = null,
        val saved: Boolean = false,
        val options: GeneratorOptions = GeneratorOptions(),
        val entropyBits: Double? = null,
    )

    val form = MutableStateFlow(Form())
    private val _state = MutableStateFlow(State(loaded = id == null))
    val state = _state.asStateFlow()
    val isNew = id == null

    init {
        viewModelScope.launch {
            try {
                _state.value = _state.value.copy(options = c.core.defaultGeneratorOptions())
            } catch (_: Exception) {
                // keep local defaults
            }
            updateEntropy()
            if (id != null) {
                try {
                    val e = c.vault.getEntry(id)
                    form.value = Form(e.title, e.username, e.password, e.urls.joinToString("\n"), e.notes)
                    _state.value = _state.value.copy(loaded = true)
                } catch (e: Exception) {
                    _state.value = _state.value.copy(error = e.errorCode(), loaded = true)
                }
            }
        }
        viewModelScope.launch {
            c.vault.status.collect { if (it != VaultManager.Status.UNLOCKED) form.value = Form() }
        }
    }

    fun setOptions(o: GeneratorOptions) {
        _state.value = _state.value.copy(options = o)
        updateEntropy()
    }

    private fun updateEntropy() {
        _state.value = _state.value.copy(entropyBits = runCatching { c.core.passwordEntropyBits(_state.value.options) }.getOrNull())
    }

    fun generate() {
        try {
            form.value = form.value.copy(password = c.core.generatePassword(_state.value.options))
            _state.value = _state.value.copy(error = null)
        } catch (e: Exception) {
            _state.value = _state.value.copy(error = e.errorCode())
        }
    }

    fun save() {
        val f = form.value
        if (f.title.isBlank()) {
            _state.value = _state.value.copy(error = ERR_TITLE)
            return
        }
        val input = EntryInput(
            title = f.title.trim(),
            username = f.username.trim(),
            password = f.password,
            urls = f.urls.lines().map { it.trim() }.filter { it.isNotEmpty() },
            notes = f.notes,
        )
        _state.value = _state.value.copy(busy = true, error = null)
        viewModelScope.launch {
            try {
                val now = c.vault.now()
                c.vault.mutate { s -> if (id == null) s.createEntry(input, now) else s.updateEntry(id, input, now) }
                _state.value = _state.value.copy(busy = false, saved = true)
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    busy = false,
                    error = e.errorCode(),
                    errorDetail = (e as? com.keyvora.app.core.CoreException)?.detail,
                )
            }
        }
    }

    companion object {
        const val ERR_TITLE = "UI_TITLE"
    }
}

@Composable
fun EntryEditScreen(id: String?, onDone: () -> Unit) {
    val vm = appViewModel(key = "edit-${id ?: "new"}") { EntryEditViewModel(it, id) }
    val f by vm.form.collectAsStateWithLifecycle()
    val st by vm.state.collectAsStateWithLifecycle()
    LaunchedEffect(st.saved) { if (st.saved) onDone() }
    ScreenScaffold(
        if (vm.isNew) "Nueva entrada" else "Editar entrada",
        onBack = onDone,
        actions = { TextButton(onClick = { vm.save() }, enabled = st.loaded && !st.busy) { Text("Guardar") } },
    ) {
        if (!st.loaded) {
            Text("Cargando…")
            return@ScreenScaffold
        }
        KvTextField(f.title, { vm.form.value = f.copy(title = it) }, "Título", leadingIcon = KvIcons.Notes)
        KvTextField(f.username, { vm.form.value = f.copy(username = it) }, "Usuario o correo", leadingIcon = Icons.Filled.Person)
        SecretField(
            f.password,
            { vm.form.value = f.copy(password = it) },
            "Contraseña",
            monospace = true,
            leadingIcon = KvIcons.Key,
            extraAction = { IconButton(onClick = vm::generate) { Icon(Icons.Filled.Refresh, contentDescription = "Generar contraseña") } },
        )
        GeneratorCard(st.options, st.entropyBits, vm::setOptions, vm::generate)
        KvTextField(
            f.urls,
            { vm.form.value = f.copy(urls = it) },
            "Sitios web o apps (uno por línea)",
            leadingIcon = KvIcons.Link,
            singleLine = false,
            minLines = 2,
            supporting = "Ej.: https://ejemplo.com o androidapp://com.ejemplo.app",
            keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri,
        )
        KvTextField(f.notes, { vm.form.value = f.copy(notes = it) }, "Notas", singleLine = false, minLines = 3)
        val err = when (st.error) {
            null -> null
            EntryEditViewModel.ERR_TITLE -> "El título es obligatorio."
            else -> errorMessage(st.error, st.errorDetail)
        }
        err?.let { Notice(it, NoticeKind.ERROR) }
        BusyButton("Guardar", st.busy) { vm.save() }
    }
}

/**
 * Password generator (shared by the entry editor and the autofill «Generar contraseña» screen): a one-tap
 * «Generar» plus collapsible options (length, character classes).
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun GeneratorCard(o: GeneratorOptions, entropyBits: Double?, onOptions: (GeneratorOptions) -> Unit, onGenerate: () -> Unit) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Generador de contraseñas", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "${o.length} caracteres" + (entropyBits?.let { " · ≈ ${it.roundToInt()} bits de entropía" } ?: ""),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(
                        if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                        contentDescription = if (expanded) "Ocultar opciones" else "Opciones del generador",
                    )
                }
            }
            AnimatedVisibility(expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Longitud: ${o.length}", style = MaterialTheme.typography.bodyMedium)
                    Slider(
                        value = o.length.toFloat(),
                        onValueChange = { onOptions(o.copy(length = it.roundToInt())) },
                        valueRange = 8f..64f,
                    )
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Chip("abc", o.lowercase) { onOptions(o.copy(lowercase = it)) }
                        Chip("ABC", o.uppercase) { onOptions(o.copy(uppercase = it)) }
                        Chip("123", o.digits) { onOptions(o.copy(digits = it)) }
                        Chip("#$%", o.symbols) { onOptions(o.copy(symbols = it)) }
                        Chip("Sin ambiguos (0/O, 1/l)", o.excludeAmbiguous) { onOptions(o.copy(excludeAmbiguous = it)) }
                    }
                }
            }
            OutlinedButton(onClick = onGenerate, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("  Generar contraseña")
            }
        }
    }
}

@Composable
private fun Chip(label: String, selected: Boolean, onChange: (Boolean) -> Unit) {
    FilterChip(
        selected = selected,
        onClick = { onChange(!selected) },
        label = { Text(label) },
        leadingIcon = if (selected) {
            { Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.size(FilterChipDefaults.IconSize)) }
        } else {
            null
        },
    )
}

@Composable
fun Toggle(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
