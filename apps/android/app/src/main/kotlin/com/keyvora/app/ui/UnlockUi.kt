package com.keyvora.app.ui

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.keyvora.app.AppContainer
import com.keyvora.app.core.CoreException
import com.keyvora.app.security.BiometricUnlock
import com.keyvora.app.security.MasterPasswordPolicy
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.crypto.Cipher


class UnlockViewModel(private val c: AppContainer) : ViewModel() {
    data class State(val busy: Boolean = false, val error: String? = null, val biometricEnabled: Boolean = false)

    private val _state = MutableStateFlow(State(biometricEnabled = c.biometric.isEnabled()))
    val state = _state.asStateFlow()

    val importPending: Boolean get() = c.settings.importPending

    private fun run(block: suspend () -> Unit) {
        if (_state.value.busy) return
        _state.value = _state.value.copy(busy = true, error = null)
        viewModelScope.launch {
            val err = try {
                block()
                null
            } catch (e: Exception) {
                e.errorCode()
            }
            _state.value = _state.value.copy(busy = false, error = err, biometricEnabled = c.biometric.isEnabled())
        }
    }

    /** Re-reads whether biometric unlock is enabled (it may have changed since this ViewModel was created). */
    fun refreshBiometric() {
        _state.value = _state.value.copy(biometricEnabled = c.biometric.isEnabled())
    }

    fun unlockWithPassword(master: String) = run { c.vault.unlockWithPassword(master) }

    fun unlockWithRecovery(recoveryKey: String, next: String, confirm: String) {
        when (MasterPasswordPolicy.validate(next, confirm)) {
            MasterPasswordPolicy.Problem.TOO_SHORT -> _state.value = _state.value.copy(error = ERR_SHORT)
            MasterPasswordPolicy.Problem.MISMATCH -> _state.value = _state.value.copy(error = ERR_MISMATCH)
            null -> run { c.vault.unlockWithRecoveryKey(recoveryKey.trim(), next) }
        }
    }

    /** Returns a cipher for BiometricPrompt, or null (error state set) if biometrics are unusable. */
    fun prepareBiometric(): Cipher? = when (val p = c.biometric.prepareUnlock()) {
        is BiometricUnlock.Prepared.Ready -> p.cipher
        BiometricUnlock.Prepared.Invalidated -> {
            _state.value = _state.value.copy(error = ERR_BIOMETRIC_INVALIDATED, biometricEnabled = false)
            null
        }
        BiometricUnlock.Prepared.NotEnabled -> {
            _state.value = _state.value.copy(biometricEnabled = false)
            null
        }
    }

    fun onBiometricSuccess(cipher: Cipher) = run { c.biometric.finishUnlock(cipher) }

    fun onBiometricError(message: String?) {
        if (message != null) _state.value = _state.value.copy(error = ERR_BIOMETRIC + message)
    }

    fun discardImport() = run { c.vault.discardPendingImport() }

    companion object {
        const val ERR_SHORT = "UI_SHORT"
        const val ERR_MISMATCH = "UI_MISMATCH"
        const val ERR_BIOMETRIC = "UI_BIO:"
    }
}

fun unlockError(code: String?): String? = when {
    code == null -> null
    code == UnlockViewModel.ERR_SHORT -> MasterPasswordPolicy.message(MasterPasswordPolicy.Problem.TOO_SHORT)
    code == UnlockViewModel.ERR_MISMATCH -> MasterPasswordPolicy.message(MasterPasswordPolicy.Problem.MISMATCH)
    code.startsWith(UnlockViewModel.ERR_BIOMETRIC) -> "Biometría: " + code.removePrefix(UnlockViewModel.ERR_BIOMETRIC)
    code == CoreException.INVALID_CREDENTIALS -> "Contraseña maestra incorrecta."
    else -> errorMessage(code)
}

fun showBiometricPrompt(
    activity: FragmentActivity,
    title: String,
    subtitle: String,
    cipher: Cipher,
    onSuccess: (Cipher) -> Unit,
    onError: (String?) -> Unit,
) {
    val prompt = BiometricPrompt(
        activity,
        ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val c = result.cryptoObject?.cipher
                if (c != null) onSuccess(c) else onError("sin objeto criptográfico")
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                val cancelled = errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                    errorCode == BiometricPrompt.ERROR_USER_CANCELED || errorCode == BiometricPrompt.ERROR_CANCELED
                onError(if (cancelled) null else errString.toString())
            }
        },
    )
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setNegativeButtonText("Usar contraseña")
        .setAllowedAuthenticators(BIOMETRIC_STRONG)
        .build()
    prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
}

/** Password (+ biometric) unlock form, shared by the app and the autofill activities. */
@Composable
fun UnlockPanel(vm: UnlockViewModel, headline: String?, autoBiometric: Boolean = true) {
    val state by vm.state.collectAsStateWithLifecycle()
    // Secrets: `remember`, never `rememberSaveable` (saved state outlives the lock, QA-006 AND-SEC-3).
    var password by remember { mutableStateOf("") }
    val activity = LocalContext.current.findFragmentActivity()

    fun biometric() {
        val a = activity ?: return
        val cipher = vm.prepareBiometric() ?: return
        showBiometricPrompt(a, "Desbloquear Keyvora", "Usa tu huella o rostro", cipher, vm::onBiometricSuccess, vm::onBiometricError)
    }

    // Each time the unlock panel is shown: refresh the biometric state (it may have been enabled or invalidated while
    // the app was unlocked, with this ViewModel still alive) and then offer it automatically.
    LaunchedEffect(Unit) {
        vm.refreshBiometric()
        if (autoBiometric && vm.state.value.biometricEnabled) biometric()
    }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        if (headline != null) Text(headline, style = MaterialTheme.typography.titleMedium)
        SecretField(
            password,
            { password = it },
            "Contraseña maestra",
            leadingIcon = KvIcons.Key,
            onDone = { if (password.isNotEmpty() && !state.busy) vm.unlockWithPassword(password) },
        )
        unlockError(state.error)?.let { Notice(it, NoticeKind.ERROR) }
        BusyButton("Desbloquear", state.busy, enabled = password.isNotEmpty()) {
            vm.unlockWithPassword(password)
        }
        if (state.biometricEnabled) {
            OutlinedButton(onClick = { biometric() }, enabled = !state.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
                Icon(KvIcons.Fingerprint, contentDescription = null, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(8.dp))
                Text("Desbloquear con biometría")
            }
        }
    }
}

/** Full unlock screen of the app (password / biometric / recovery key). */
@Composable
fun UnlockScreen() {
    val vm = appViewModel { UnlockViewModel(it) }
    var recovery by rememberSaveable { mutableStateOf(false) }
    var confirmDiscard by rememberSaveable { mutableStateOf(false) }
    if (recovery) {
        RecoveryUnlockScreen(vm) { recovery = false }
        return
    }
    Scaffold { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(48.dp))
            BrandMark(96.dp)
            Text("Keyvora", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold)
            Text(
                "Tu bóveda está bloqueada",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(8.dp))
            UnlockPanel(vm, headline = null)
            TextButton(onClick = { recovery = true }) { Text("¿Olvidaste la contraseña? Usar clave de recuperación") }
            if (vm.importPending) {
                Notice("Esta bóveda se importó y aún no se ha desbloqueado nunca en este dispositivo.") {
                    TextButton(onClick = { confirmDiscard = true }) { Text("Descartar la bóveda importada") }
                }
            }
        }
    }
    if (confirmDiscard) {
        ConfirmDialog(
            title = "¿Descartar la bóveda importada?",
            text = "Se borrará la copia importada de este dispositivo. El archivo original no se modifica.",
            confirm = "Descartar",
            onConfirm = { confirmDiscard = false; vm.discardImport() },
            onDismiss = { confirmDiscard = false },
        )
    }
}

@Composable
private fun RecoveryUnlockScreen(vm: UnlockViewModel, onBack: () -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    var key by remember { mutableStateOf("") }
    var next by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    ScreenScaffold("Clave de recuperación", onBack = onBack) {
        Text(
            "Introduce tu clave de recuperación (14 grupos de 4 caracteres). Después elegirás una nueva contraseña maestra.",
            style = MaterialTheme.typography.bodyLarge,
        )
        // Password keyboard: no learning/suggestions/cloud sync of the recovery key (AND-SEC-4).
        SecretField(key, { key = it }, "Clave de recuperación", monospace = true, leadingIcon = KvIcons.Shield)
        SecretField(next, { next = it }, "Nueva contraseña maestra", leadingIcon = KvIcons.Key)
        StrengthMeter(next)
        SecretField(confirm, { confirm = it }, "Repite la nueva contraseña", leadingIcon = KvIcons.Key)
        unlockError(state.error)?.let { Notice(it, NoticeKind.ERROR) }
        BusyButton("Recuperar acceso", state.busy, enabled = key.isNotBlank() && next.isNotEmpty()) {
            vm.unlockWithRecovery(key, next, confirm)
        }
    }
}

/** Shows the recovery key once: requires "La he guardado" + typing the last group. */
@Composable
fun RecoveryKeyScreen(recoveryKey: String, onDone: () -> Unit) {
    val c = LocalAppContainer.current
    var saved by rememberSaveable { mutableStateOf(false) }
    var typed by remember { mutableStateOf("") }
    val groups = recoveryKey.split('-')
    val last = groups.lastOrNull().orEmpty()
    ScreenScaffold("Clave de recuperación") {
        Text(
            "Es la única forma de recuperar la bóveda si olvidas la contraseña maestra. Guárdala fuera del dispositivo " +
                "(en papel o en un lugar seguro).",
            style = MaterialTheme.typography.bodyLarge,
        )
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
        ) {
            Text(
                groups.chunked(4).joinToString("\n") { it.joinToString("  ") },
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.titleLarge,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(vertical = 20.dp, horizontal = 12.dp),
            )
        }
        OutlinedButton(onClick = { c.clipboard.copy(recoveryKey) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
            Icon(KvIcons.Copy, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text("Copiar (se borra del portapapeles en 30 s)")
        }
        Notice("No se volverá a mostrar y Keyvora no la guarda.", NoticeKind.WARNING)
        Row(
            Modifier.fillMaxWidth().toggleable(value = saved, role = Role.Checkbox, onValueChange = { saved = it }),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = saved, onCheckedChange = null)
            Spacer(Modifier.width(12.dp))
            Text("La he guardado en un lugar seguro", style = MaterialTheme.typography.bodyLarge)
        }
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it },
            label = { Text("Escribe el último grupo para confirmar") },
            singleLine = true,
            shape = RoundedCornerShape(14.dp),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth(),
            textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
        )
        BusyButton("Continuar", busy = false, enabled = saved && typed.trim().equals(last, ignoreCase = true)) {
            c.clipboard.clearIfOurs()
            onDone()
        }
    }
}
