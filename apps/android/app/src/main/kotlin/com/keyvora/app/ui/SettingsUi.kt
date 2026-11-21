package com.keyvora.app.ui

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Switch
import androidx.compose.ui.semantics.Role
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.keyvora.app.AppContainer
import com.keyvora.app.autofill.AutofillTrust
import com.keyvora.app.autofill.PinKind
import com.keyvora.app.core.CoreException
import com.keyvora.app.core.EntrySummary
import com.keyvora.app.core.KdfParams
import com.keyvora.app.security.MasterPasswordPolicy
import com.keyvora.app.sync.KeyringAdoption
import com.keyvora.app.sync.RevisionInfo
import com.keyvora.app.vault.AutoLockDelay
import com.keyvora.app.vault.ThemeMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date
import javax.crypto.Cipher

class SettingsViewModel(private val c: AppContainer) : ViewModel() {
    data class State(
        val autoLock: AutoLockDelay,
        val biometricEnabled: Boolean,
        val biometricAvailable: Boolean,
        val biometricNeedsReenable: Boolean = false,
        val kdf: KdfParams? = null,
        val kdfWeak: Boolean = false,
        val pins: List<Triple<PinKind, String, Set<String>>> = emptyList(),
        val busy: Boolean = false,
        val message: String? = null,
        val error: String? = null,
    )

    private val _state = MutableStateFlow(read())
    val state = _state.asStateFlow()
    val sync = c.sync.ui
    val deviceId: String get() = c.settings.deviceId
    val coreAvailable: Boolean get() = c.core.isAvailable

    private fun read() = State(
        c.settings.autoLock, c.biometric.isEnabled(), c.biometric.isHardwareAvailable(),
        biometricNeedsReenable = c.settings.biometricNeedsReenable,
        kdf = _kdf, kdfWeak = _kdfWeak, pins = c.trustPins.all(),
    )

    private var _kdf: KdfParams? = null
    private var _kdfWeak = false

    init {
        viewModelScope.launch {
            try {
                val p = c.vault.passwordKdfParams()
                val d = c.core.defaultKdfParams()
                _kdf = p
                _kdfWeak = p.memoryKib < d.memoryKib || p.iterations < d.iterations
                _state.value = _state.value.copy(kdf = _kdf, kdfWeak = _kdfWeak)
            } catch (_: Exception) {
                // locked / no core: nothing to show
            }
        }
    }

    fun forgetPin(kind: PinKind, pkg: String) {
        c.trustPins.forget(kind, pkg)
        _state.value = _state.value.copy(pins = c.trustPins.all(), message = "Se olvidó el certificado de $pkg.")
    }

    fun rotateDataKey(current: String) = run {
        val rk = c.vault.rotateDataKey(current)
        c.recoveryKey.set(rk)
    }

    private fun run(success: String? = null, block: suspend () -> Unit) {
        _state.value = _state.value.copy(busy = true, message = null, error = null)
        viewModelScope.launch {
            try {
                block()
                _state.value = read().copy(message = success)
            } catch (e: Exception) {
                _state.value = read().copy(error = e.errorCode())
            }
        }
    }

    fun setTheme(mode: ThemeMode) {
        c.settings.themeMode = mode
        c.themeMode.value = mode
    }

    fun setAutoLock(d: AutoLockDelay) {
        c.settings.autoLock = d
        c.autoLock.onDelayChanged()
        _state.value = _state.value.copy(autoLock = d)
    }

    fun prepareBiometricEnable(): Cipher? = try {
        c.biometric.prepareEnable()
    } catch (e: Exception) {
        _state.value = _state.value.copy(error = ERR_BIO_SETUP)
        null
    }

    fun finishBiometricEnable(cipher: Cipher) = run("Biometría activada.") { c.biometric.finishEnable(cipher) }

    /**
     * Biometrics wrap a copy of the data key: enabling them needs the master password, not just an unlocked session,
     * so someone holding the phone while the vault is open cannot add their own fingerprint access (AUDIT AND-7).
     */
    fun verifyMasterForBiometric(master: String, onVerified: () -> Unit) {
        _state.value = _state.value.copy(busy = true, message = null, error = null)
        viewModelScope.launch {
            try {
                c.vault.verifyMasterPassword(master)
                _state.value = read()
                onVerified()
            } catch (e: Exception) {
                _state.value = read().copy(error = e.errorCode())
            }
        }
    }

    fun disableBiometric() {
        c.biometric.disable()
        _state.value = read().copy(message = "Biometría desactivada.")
    }

    fun changePassword(current: String, next: String, confirm: String): Boolean {
        val err = when (MasterPasswordPolicy.validate(next, confirm)) {
            MasterPasswordPolicy.Problem.TOO_SHORT -> UnlockViewModel.ERR_SHORT
            MasterPasswordPolicy.Problem.MISMATCH -> UnlockViewModel.ERR_MISMATCH
            null -> null
        }
        if (err != null) {
            _state.value = _state.value.copy(error = err)
            return false
        }
        run("Contraseña maestra cambiada. Guarda la nueva clave de recuperación: la anterior ya no funciona.") {
            c.recoveryKey.set(c.vault.changeMasterPassword(current, next))
        }
        return true
    }

    fun rotateRecovery(current: String) = run {
        val rk = c.vault.rotateRecoveryKey(current)
        c.recoveryKey.set(rk)
    }

    fun export(context: Context, uri: Uri) = run("Copia cifrada exportada.") {
        writeDocument(context, uri, c.vault.exportBackup())
    }

    fun import(context: Context, uri: Uri) {
        _state.value = _state.value.copy(busy = true, message = null, error = null)
        viewModelScope.launch {
            val text = try {
                readDocument(context, uri)
            } catch (e: Exception) {
                _state.value = read().copy(error = e.errorCode())
                return@launch
            }
            try {
                val r = c.vault.importMerge(text)
                _state.value = read().copy(
                    message = "Copia fusionada: ${r.added} nuevas, ${r.updated} actualizadas, ${r.removed} eliminadas" +
                        (if (r.newConflicts.isNotEmpty()) ", ${r.newConflicts.size} conflictos." else "."),
                )
            } catch (e: CoreException) {
                if (e.code == CoreException.KEYRING_CHANGED) {
                    c.keyring.offer(KeyringAdoption.Source.IMPORT, text) // asks for the copy's master password
                    _state.value = read()
                } else {
                    _state.value = read().copy(error = e.code)
                }
            } catch (e: Exception) {
                _state.value = read().copy(error = e.errorCode())
            }
        }
    }

    fun onDriveConnected(ok: Boolean) {
        if (ok) {
            c.sync.onConnected()
            _state.value = _state.value.copy(message = "Google Drive conectado.", error = null)
        } else {
            _state.value = _state.value.copy(error = ERR_DRIVE_DENIED)
        }
    }

    fun syncNow() = run {
        val r = c.sync.syncNow()
        if (r?.error != null) throw com.keyvora.app.core.CoreException(r.error)
    }

    fun disconnectDrive() {
        c.sync.disconnect()
        _state.value = _state.value.copy(message = "Google Drive desconectado. Los datos locales no cambian.")
    }

    fun lockNow() = c.vault.lock()

    companion object {
        const val ERR_BIO_SETUP = "UI_BIO_SETUP"
    }
}

@Composable
fun SettingsScreen(onBack: () -> Unit, onRestore: () -> Unit) {
    val vm = appViewModel { SettingsViewModel(it) }
    val st by vm.state.collectAsStateWithLifecycle()
    val sync by vm.sync.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val c = LocalAppContainer.current
    var dialog by rememberSaveable { mutableStateOf<String?>(null) }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null) vm.export(ctx, uri)
    }
    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.import(ctx, uri)
    }
    val connect = rememberDriveConnector(vm::onDriveConnected)

    ScreenScaffold("Ajustes", onBack = onBack) {
        st.message?.let { Notice(it, NoticeKind.SUCCESS) }
        settingsError(st.error)?.let { Notice(it, NoticeKind.ERROR) }

        val theme by c.themeMode.collectAsStateWithLifecycle()
        SectionCard("Apariencia", KvIcons.Contrast) {
            listOf(
                ThemeMode.SYSTEM to "Según el sistema",
                ThemeMode.LIGHT to "Claro",
                ThemeMode.DARK to "Oscuro",
            ).forEach { (mode, label) ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .selectable(selected = theme == mode, role = Role.RadioButton, onClick = { vm.setTheme(mode) })
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = theme == mode, onClick = null, modifier = Modifier.padding(12.dp))
                    Text(label, style = MaterialTheme.typography.bodyLarge)
                }
            }
        }

        SectionCard("Bloqueo automático", KvIcons.Timer) {
            AutoLockDelay.entries.forEach { d ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .selectable(selected = st.autoLock == d, role = Role.RadioButton, onClick = { vm.setAutoLock(d) })
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = st.autoLock == d, onClick = null, modifier = Modifier.padding(12.dp))
                    Text(if (d == AutoLockDelay.IMMEDIATE) "Inmediato al salir de la app" else "Tras ${d.minutes} min", style = MaterialTheme.typography.bodyLarge)
                }
            }
            Text(
                "Con la app abierta también se bloquea tras ese tiempo sin actividad (mínimo 1 min).",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = CardTextPadding,
            )
        }

        SectionCard("Biometría", KvIcons.Fingerprint) {
            SettingsRow(
                KvIcons.Fingerprint,
                "Desbloquear con biometría",
                if (st.biometricAvailable) "Huella o rostro de este dispositivo" else "Este dispositivo no tiene biometría fuerte configurada",
                enabled = st.biometricAvailable || st.biometricEnabled,
                trailing = {
                    Switch(
                        checked = st.biometricEnabled,
                        enabled = st.biometricAvailable || st.biometricEnabled,
                        onCheckedChange = { on ->
                            if (!on) vm.disableBiometric() else dialog = "biometric"
                        },
                    )
                },
            )
            if (st.biometricNeedsReenable && !st.biometricEnabled) {
                Column(CardTextPadding) {
                    Notice("La clave de cifrado cambió y se desactivó la biometría. Vuelve a activarla si quieres usarla.", NoticeKind.WARNING)
                }
            }
            Text(
                "Solo desbloquea una clave guardada en este dispositivo; no sustituye a la contraseña maestra ni se sincroniza.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = CardTextPadding,
            )
        }

        SectionCard("Seguridad", KvIcons.Shield) {
            SettingsRow(KvIcons.Key, "Cambiar contraseña maestra", enabled = !st.busy) { dialog = "password" }
            SettingsRow(KvIcons.Shield, "Generar nueva clave de recuperación", "La anterior dejará de funcionar", enabled = !st.busy) { dialog = "recovery" }
            SettingsRow(Icons.Filled.Refresh, "Rotar clave de cifrado", "Si crees que alguien obtuvo tu bóveda o tu clave", enabled = !st.busy) { dialog = "rotate" }
            SettingsRow(Icons.Filled.Lock, "Bloquear ahora", onClick = vm::lockNow)
            st.kdf?.let { k ->
                Text(
                    "Derivación de la contraseña: Argon2id, ${k.memoryKib / 1024} MiB, ${k.iterations} iteraciones, paralelismo ${k.parallelism}.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = CardTextPadding,
                )
                if (st.kdfWeak) {
                    Column(CardTextPadding) {
                        Notice("Estos parámetros son más débiles que los recomendados. Cambia la contraseña maestra para reforzarlos.", NoticeKind.WARNING)
                    }
                }
            }
        }

        SectionCard("Sincronización con Google Drive", KvIcons.Cloud) {
            if (!sync.connected) {
                Text(
                    "No conectado. Solo se sube el contenedor cifrado a la carpeta oculta de la app (appDataFolder).",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = CardTextPadding,
                )
                SettingsRow(KvIcons.Cloud, "Conectar Google Drive", enabled = !st.busy, onClick = connect)
            } else {
                val last = sync.state.lastSyncAt?.let { DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(it)) } ?: "nunca"
                SettingsRow(
                    KvIcons.Cloud,
                    if (sync.running) "Sincronizando…" else "Conectado",
                    "Última sincronización: $last" + if (sync.state.dirty) " · cambios pendientes de subir" else "",
                )
                sync.state.lastError?.let { err ->
                    Column(CardTextPadding) { Notice(errorMessage(err), NoticeKind.ERROR) }
                }
                if (sync.state.lastError == com.keyvora.app.sync.RemoteErrorCode.AUTH_REQUIRED.name) {
                    SettingsRow(KvIcons.Key, "Volver a conectar", onClick = connect)
                }
                if (sync.state.rollbackWarning) {
                    Column(CardTextPadding) { Notice("Aviso de posible rollback en Drive (ver la lista de entradas).", NoticeKind.WARNING) }
                }
                SettingsRow(Icons.Filled.Refresh, "Sincronizar ahora", enabled = !sync.running && !st.busy, onClick = vm::syncNow)
                SettingsRow(KvIcons.Cloud, "Desconectar", danger = true) { dialog = "disconnect" }
            }
        }

        SectionCard("Copia cifrada", KvIcons.Download) {
            Text(
                "El archivo exportado está cifrado: solo se abre con tu contraseña maestra o tu clave de recuperación.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = CardTextPadding,
            )
            SettingsRow(KvIcons.Download, "Exportar copia cifrada", enabled = !st.busy) {
                c.autoLock.expectExternalActivity(); exportLauncher.launch("keyvora-copia.json")
            }
            SettingsRow(KvIcons.Upload, "Importar copia cifrada (fusionar)", enabled = !st.busy) {
                c.autoLock.expectExternalActivity(); importLauncher.launch(arrayOf("application/json", "application/octet-stream", "text/plain"))
            }
            SettingsRow(KvIcons.History, "Restaurar entradas de una versión anterior", enabled = !st.busy, onClick = onRestore)
        }

        SectionCard("Apps de confianza", KvIcons.Apps) {
            Text(
                "Certificados de firma de las apps que asociaste para el autorrelleno (solo en este dispositivo). " +
                    "Los navegadores no aparecen aquí: Keyvora solo acepta los firmados con su certificado oficial.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = CardTextPadding,
            )
            if (st.pins.isEmpty()) {
                Text("Ninguno todavía.", style = MaterialTheme.typography.bodyMedium, modifier = CardTextPadding)
            }
            st.pins.forEach { (kind, pkg, digests) ->
                SettingsRow(
                    KvIcons.Apps,
                    pkg,
                    "App · " + digests.joinToString(", ") { AutofillTrust.formatDigest(it).take(11) + "…" },
                    trailing = { TextButton(onClick = { vm.forgetPin(kind, pkg) }) { Text("Olvidar") } },
                )
            }
        }

        SectionCard("Acerca de", Icons.Filled.Info) {
            SettingsRow(null, "Núcleo criptográfico", if (vm.coreAvailable) "Incluido" else "NO incluido en esta compilación")
            SettingsRow(null, "Id de este dispositivo", vm.deviceId)
        }
        Spacer(Modifier.width(1.dp))
    }

    when (dialog) {
        "password" -> ChangePasswordDialog(onDismiss = { dialog = null }) { cur, next, conf ->
            if (vm.changePassword(cur, next, conf)) dialog = null
        }
        "recovery" -> RotateRecoveryDialog(onDismiss = { dialog = null }) { cur ->
            dialog = null
            vm.rotateRecovery(cur)
        }
        "rotate" -> RotateDataKeyDialog(onDismiss = { dialog = null }) { cur ->
            dialog = null
            vm.rotateDataKey(cur)
        }
        "biometric" -> BiometricPasswordDialog(onDismiss = { dialog = null }) { cur ->
            dialog = null
            vm.verifyMasterForBiometric(cur) {
                val activity = ctx.findFragmentActivity()
                val cipher = vm.prepareBiometricEnable()
                if (activity != null && cipher != null) {
                    showBiometricPrompt(activity, "Activar biometría", "Confirma con tu huella o rostro", cipher, vm::finishBiometricEnable) { }
                }
            }
        }
        "disconnect" -> ConfirmDialog(
            title = "¿Desconectar Google Drive?",
            text = "Se dejará de sincronizar en este dispositivo. No se borra nada ni aquí ni en Drive. " +
                "Puedes revocar el acceso en la configuración de tu cuenta de Google.",
            confirm = "Desconectar",
            onConfirm = { dialog = null; vm.disconnectDrive() },
            onDismiss = { dialog = null },
        )
    }
}

fun settingsError(code: String?): String? = when (code) {
    null -> null
    SettingsViewModel.ERR_BIO_SETUP -> "No se pudo preparar la biometría (¿hay una huella o rostro registrado?)."
    else -> setupError(code)
}

@Composable
private fun ChangePasswordDialog(onDismiss: () -> Unit, onConfirm: (String, String, String) -> Unit) {
    var cur by remember { mutableStateOf("") }
    var next by remember { mutableStateOf("") }
    var conf by remember { mutableStateOf("") }
    SecureAlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Cambiar contraseña maestra") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SecretField(cur, { cur = it }, "Contraseña actual")
                SecretField(next, { next = it }, "Nueva contraseña")
                SecretField(conf, { conf = it }, "Repite la nueva contraseña")
                Text(MasterPasswordPolicy.hint(next), style = MaterialTheme.typography.bodySmall)
                Text("Los demás dispositivos te pedirán la nueva contraseña al sincronizar.", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(cur, next, conf) }, enabled = cur.isNotEmpty() && next.isNotEmpty()) { Text("Cambiar") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}

@Composable
private fun BiometricPasswordDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var cur by remember { mutableStateOf("") }
    SecureAlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Activar biometría") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "La biometría guarda en este dispositivo una copia protegida de tu clave de cifrado. Para activarla, " +
                        "confirma que eres tú con la contraseña maestra.",
                )
                SecretField(cur, { cur = it }, "Contraseña maestra")
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(cur) }, enabled = cur.isNotEmpty()) { Text("Continuar") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}

@Composable
private fun RotateDataKeyDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var cur by remember { mutableStateOf("") }
    SecureAlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Rotar clave de cifrado") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Se generan una clave de cifrado nueva y una clave de recuperación nueva (se mostrará una vez). " +
                        "Úsalo si crees que alguien obtuvo tu bóveda desbloqueada o tu clave de recuperación.",
                )
                Text(
                    "Solo protege los datos guardados a partir de ahora: quien ya tenga una copia antigua con la clave " +
                        "anterior podrá seguir leyendo esa copia. Los demás dispositivos te pedirán la contraseña maestra " +
                        "y la biometría deberá activarse de nuevo.",
                    style = MaterialTheme.typography.bodySmall,
                )
                SecretField(cur, { cur = it }, "Contraseña maestra actual")
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(cur) }, enabled = cur.isNotEmpty()) { Text("Rotar") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}

@Composable
private fun RotateRecoveryDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var cur by remember { mutableStateOf("") }
    SecureAlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Nueva clave de recuperación") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("La clave de recuperación anterior dejará de funcionar. Confirma con tu contraseña maestra.")
                SecretField(cur, { cur = it }, "Contraseña maestra")
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(cur) }, enabled = cur.isNotEmpty()) { Text("Generar") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}

// ------------------------------------------------------------------------------------------------ restore

class RestoreViewModel(private val c: AppContainer) : ViewModel() {
    data class State(
        val busy: Boolean = false,
        val error: String? = null,
        val revisions: List<RevisionInfo>? = null,
        val preview: List<EntrySummary>? = null,
        val currentIds: Set<String> = emptySet(),
        val restored: Int? = null,
    )

    private val _state = MutableStateFlow(State())
    val state = _state.asStateFlow()
    private var container: String? = null
    private var fileId: String? = null
    val driveConnected: Boolean get() = c.settings.driveConnected

    private fun run(block: suspend () -> Unit) {
        _state.value = _state.value.copy(busy = true, error = null)
        viewModelScope.launch {
            try {
                block()
                _state.value = _state.value.copy(busy = false)
            } catch (e: Exception) {
                _state.value = _state.value.copy(busy = false, error = e.errorCode())
            }
        }
    }

    private suspend fun preview(text: String) {
        val list = c.vault.previewContainer(text)
        container = text
        val current = c.vault.listEntries("").map { it.id }.toSet()
        _state.value = _state.value.copy(preview = list, currentIds = current, restored = null)
    }

    fun fromFile(context: Context, uri: Uri) = run { preview(readDocument(context, uri)) }

    fun listDriveRevisions() = run {
        val store = c.driveStore()
        val meta = store.getMetadata() ?: throw IllegalStateException(SetupViewModel.ERR_NO_REMOTE)
        fileId = meta.fileId
        _state.value = _state.value.copy(revisions = store.listRevisions(meta.fileId).reversed(), preview = null)
    }

    fun fromRevision(rev: RevisionInfo) = run {
        val id = fileId ?: return@run
        preview(c.driveStore().downloadRevision(id, rev.id))
    }

    fun restore(ids: List<String>) = run {
        val text = container ?: return@run
        val restored = c.vault.restoreEntries(text, ids)
        _state.value = _state.value.copy(restored = restored.size, preview = null)
    }
}

@Composable
fun RestoreScreen(onBack: () -> Unit) {
    val vm = appViewModel { RestoreViewModel(it) }
    val st by vm.state.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val c = LocalAppContainer.current
    val selected = remember { mutableStateOf(setOf<String>()) }
    val fileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.fromFile(ctx, uri)
    }
    ScreenScaffold("Restaurar entradas", onBack = onBack) {
        Text(
            "Elige una copia cifrada o una versión anterior de Google Drive. Las entradas que marques se copiarán como " +
                "entradas nuevas; no se sobrescribe nada.",
        )
        OutlinedButton(onClick = { c.autoLock.expectExternalActivity(); fileLauncher.launch(arrayOf("application/json", "application/octet-stream", "text/plain")) }, modifier = Modifier.fillMaxWidth(), enabled = !st.busy) {
            Text("Desde un archivo de copia")
        }
        if (vm.driveConnected) {
            OutlinedButton(onClick = vm::listDriveRevisions, modifier = Modifier.fillMaxWidth(), enabled = !st.busy) { Text("Desde una versión de Google Drive") }
        }
        if (st.busy) Text("Procesando…")
        setupError(st.error)?.let { Notice(it, NoticeKind.ERROR) }
        st.restored?.let { Notice("Se restauraron $it entradas.", NoticeKind.SUCCESS) }

        val preview = st.preview
        if (preview != null) {
            Text("Entradas en esa versión (${preview.size}):", style = MaterialTheme.typography.titleSmall)
            preview.forEach { e ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = e.id in selected.value, onCheckedChange = { on ->
                        selected.value = if (on) selected.value + e.id else selected.value - e.id
                    })
                    Column(Modifier.weight(1f)) {
                        Text(e.title)
                        Text(
                            (e.username.ifEmpty { "—" }) + if (e.id in st.currentIds) " · existe actualmente" else " · no existe actualmente",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
            BusyButton("Restaurar ${selected.value.size} seleccionadas", st.busy, enabled = selected.value.isNotEmpty()) {
                vm.restore(selected.value.toList())
                selected.value = emptySet()
            }
        } else {
            st.revisions?.let { revs ->
                Text("Versiones en Drive (más reciente primero):", style = MaterialTheme.typography.titleSmall)
                if (revs.isEmpty()) Text("No hay versiones disponibles.")
                revs.forEach { r ->
                    TextButton(onClick = { vm.fromRevision(r) }, modifier = Modifier.fillMaxWidth()) {
                        Text("${r.modifiedTime?.let(::shortDate) ?: r.id} · ${r.size?.let { "${it / 1024} KiB" } ?: ""}")
                    }
                }
            }
        }
    }
}
