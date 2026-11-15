package com.keyvora.app.ui

import android.app.Activity
import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.keyvora.app.AppContainer
import com.keyvora.app.security.MasterPasswordPolicy
import com.keyvora.app.sync.GoogleAuthProvider
import com.keyvora.app.sync.SyncState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException

const val MAX_CONTAINER_BYTES = 64 * 1024 * 1024

/** Reads a SAF document as UTF-8 text (bounded to the 64 MiB container limit). */
suspend fun readDocument(context: Context, uri: Uri): String = withContext(Dispatchers.IO) {
    val input = context.contentResolver.openInputStream(uri) ?: throw IOException("no stream")
    input.use {
        val bytes = it.readBytes()
        if (bytes.size > MAX_CONTAINER_BYTES) throw IOException("too large")
        bytes.toString(Charsets.UTF_8)
    }
}

suspend fun writeDocument(context: Context, uri: Uri, text: String) = withContext(Dispatchers.IO) {
    val out = context.contentResolver.openOutputStream(uri, "wt") ?: throw IOException("no stream")
    out.use { it.write(text.toByteArray(Charsets.UTF_8)) }
}

/** Cheap type check before storing an imported file; real validation happens in the core on unlock. */
fun looksLikeVaultContainer(text: String): Boolean = try {
    JSONObject(text).optString("format") == "keyvora.vault"
} catch (_: Exception) {
    false
}

class SetupViewModel(private val c: AppContainer) : ViewModel() {
    data class State(val busy: Boolean = false, val error: String? = null, val info: String? = null)

    private val _state = MutableStateFlow(State())
    val state = _state.asStateFlow()
    val coreAvailable: Boolean get() = c.core.isAvailable

    private fun run(block: suspend () -> Unit) {
        if (_state.value.busy) return
        _state.value = State(busy = true)
        viewModelScope.launch {
            val err = try {
                block(); null
            } catch (e: Exception) {
                e.errorCode()
            }
            _state.value = _state.value.copy(busy = false, error = err)
        }
    }

    fun create(master: String, confirm: String, acknowledged: Boolean) {
        when (MasterPasswordPolicy.validate(master, confirm)) {
            MasterPasswordPolicy.Problem.TOO_SHORT -> _state.value = State(error = UnlockViewModel.ERR_SHORT)
            MasterPasswordPolicy.Problem.MISMATCH -> _state.value = State(error = UnlockViewModel.ERR_MISMATCH)
            null -> if (!acknowledged) {
                _state.value = State(error = ERR_ACK)
            } else {
                run { c.vault.create(master) { rk -> c.recoveryKey.set(rk) } }
            }
        }
    }

    fun importFile(context: Context, uri: Uri) = run {
        val text = readDocument(context, uri)
        if (!looksLikeVaultContainer(text)) throw com.keyvora.app.core.CoreException(com.keyvora.app.core.CoreException.INVALID_FORMAT)
        c.syncState.update { SyncState() }
        c.settings.importPending = true
        c.vault.installContainer(text)
    }

    fun restoreFromDrive() = run {
        val store = c.driveStore()
        val meta = store.getMetadata() ?: throw IllegalStateException(ERR_NO_REMOTE)
        val dl = store.download(meta.fileId)
        if (!looksLikeVaultContainer(dl.content)) throw com.keyvora.app.core.CoreException(com.keyvora.app.core.CoreException.INVALID_FORMAT)
        c.syncState.update { SyncState(fileId = meta.fileId, lastSyncedHeadRevisionId = dl.headRevisionId) }
        c.settings.importPending = true
        c.settings.driveConnected = true
        c.vault.installContainer(dl.content)
    }

    fun fail(code: String) {
        _state.value = State(error = code)
    }

    companion object {
        const val ERR_ACK = "UI_ACK"
        const val ERR_NO_REMOTE = "UI_NO_REMOTE"
    }
}

fun setupError(code: String?): String? = when (code) {
    null -> null
    SetupViewModel.ERR_ACK -> "Debes confirmar que entiendes el aviso."
    "IllegalStateException", SetupViewModel.ERR_NO_REMOTE -> "No hay ninguna bóveda de Keyvora en tu Google Drive."
    ERR_DRIVE_DENIED -> "No se concedió acceso a Google Drive."
    else -> unlockError(code)
}

const val ERR_DRIVE_DENIED = "UI_DRIVE_DENIED"

/**
 * Interactive Google authorization (account picker + consent for `drive.appdata`). Returns a launcher function;
 * [onResult] receives true when access was granted.
 */
@Composable
fun rememberDriveConnector(onResult: (Boolean) -> Unit): () -> Unit {
    val c = LocalAppContainer.current
    val activity = LocalContext.current.findFragmentActivity()
    val scope = rememberCoroutineScope()
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { res ->
        onResult(res.resultCode == Activity.RESULT_OK && c.googleAuth.completeInteractive(res.data))
    }
    return {
        scope.launch {
            try {
                when (val r = c.googleAuth.beginInteractive(activity ?: return@launch onResult(false))) {
                    GoogleAuthProvider.Interactive.Granted -> onResult(true)
                    is GoogleAuthProvider.Interactive.NeedsConsent -> {
                        c.autoLock.expectExternalActivity()
                        launcher.launch(IntentSenderRequest.Builder(r.intentSender).build())
                    }
                }
            } catch (_: Exception) {
                onResult(false)
            }
        }
    }
}

@Composable
fun SetupScreen() {
    val vm = appViewModel { SetupViewModel(it) }
    var creating by rememberSaveable { mutableStateOf(false) }
    if (creating) {
        CreateVaultScreen(vm) { creating = false }
        return
    }
    val state by vm.state.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val c = LocalAppContainer.current
    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.importFile(ctx, uri)
    }
    val connect = rememberDriveConnector { ok -> if (ok) vm.restoreFromDrive() else vm.fail(ERR_DRIVE_DENIED) }

    ScreenScaffold("Bienvenido a Keyvora") {
        Text("Gestor de contraseñas con bóveda cifrada de extremo a extremo. Tus datos se cifran en este dispositivo antes de guardarse o sincronizarse.")
        if (!vm.coreAvailable) {
            Text(errorMessage(com.keyvora.app.core.CoreException.CORE_NOT_BUILT), color = MaterialTheme.colorScheme.error)
        }
        BusyButton("Crear una bóveda nueva", busy = false, enabled = !state.busy) { creating = true }
        OutlinedButton(
            onClick = { c.autoLock.expectExternalActivity(); importLauncher.launch(arrayOf("application/json", "application/octet-stream", "text/plain")) },
            enabled = !state.busy,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Importar una copia cifrada") }
        OutlinedButton(onClick = connect, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) {
            Text("Restaurar desde Google Drive")
        }
        if (state.busy) Text("Procesando…")
        setupError(state.error)?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

@Composable
private fun CreateVaultScreen(vm: SetupViewModel, onBack: () -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    var master by rememberSaveable { mutableStateOf("") }
    var confirm by rememberSaveable { mutableStateOf("") }
    var ack by rememberSaveable { mutableStateOf(false) }
    ScreenScaffold("Crear bóveda", onBack = onBack) {
        Text("Elige una contraseña maestra. Es la única llave de tu bóveda: Keyvora no la guarda ni la envía a ningún sitio.")
        SecretField(master, { master = it }, "Contraseña maestra")
        SecretField(confirm, { confirm = it }, "Repite la contraseña maestra")
        Text(MasterPasswordPolicy.hint(master), style = MaterialTheme.typography.bodySmall)
        Text(
            "Aviso: si pierdes la contraseña maestra Y la clave de recuperación, no podrás recuperar tus datos. " +
                "Nadie (ni Keyvora ni Google) puede descifrarlos por ti.",
            color = MaterialTheme.colorScheme.error,
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = ack, onCheckedChange = { ack = it })
            Text("Entiendo que la pérdida sería irreversible")
        }
        setupError(state.error)?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        BusyButton("Crear bóveda", state.busy, enabled = master.isNotEmpty()) { vm.create(master, confirm, ack) }
    }
}
