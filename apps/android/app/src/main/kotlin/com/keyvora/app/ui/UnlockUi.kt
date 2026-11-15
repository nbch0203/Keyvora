package com.keyvora.app.ui

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.foundation.layout.Row
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
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
fun UnlockPanel(vm: UnlockViewModel, headline: String, autoBiometric: Boolean = true) {
    val state by vm.state.collectAsStateWithLifecycle()
    var password by rememberSaveable { mutableStateOf("") }
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

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(headline, style = MaterialTheme.typography.titleMedium)
        SecretField(password, { password = it }, "Contraseña maestra")
        unlockError(state.error)?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        BusyButton("Desbloquear", state.busy, enabled = password.isNotEmpty()) {
            vm.unlockWithPassword(password)
        }
        if (state.biometricEnabled) {
            OutlinedButton(onClick = { biometric() }, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) {
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
    ScreenScaffold("Keyvora") {
        UnlockPanel(vm, "Tu bóveda está bloqueada")
        TextButton(onClick = { recovery = true }) { Text("Usar clave de recuperación") }
        if (vm.importPending) {
            Text(
                "Esta bóveda se importó y aún no se ha desbloqueado nunca en este dispositivo.",
                style = MaterialTheme.typography.bodySmall,
            )
            TextButton(onClick = { confirmDiscard = true }) { Text("Descartar la bóveda importada") }
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
    var key by rememberSaveable { mutableStateOf("") }
    var next by rememberSaveable { mutableStateOf("") }
    var confirm by rememberSaveable { mutableStateOf("") }
    ScreenScaffold("Clave de recuperación", onBack = onBack) {
        Text("Introduce tu clave de recuperación (14 grupos de 4 caracteres). Después deberás elegir una nueva contraseña maestra.")
        OutlinedTextField(
            value = key,
            onValueChange = { key = it },
            label = { Text("Clave de recuperación") },
            modifier = Modifier.fillMaxWidth(),
            textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
        )
        SecretField(next, { next = it }, "Nueva contraseña maestra")
        SecretField(confirm, { confirm = it }, "Repite la nueva contraseña")
        Text(MasterPasswordPolicy.hint(next), style = MaterialTheme.typography.bodySmall)
        unlockError(state.error)?.let { Text(it, color = MaterialTheme.colorScheme.error) }
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
    var typed by rememberSaveable { mutableStateOf("") }
    val groups = recoveryKey.split('-')
    val last = groups.lastOrNull().orEmpty()
    ScreenScaffold("Clave de recuperación") {
        Text(
            "Guarda esta clave fuera del dispositivo (papel o lugar seguro). Es la única forma de recuperar la bóveda " +
                "si olvidas la contraseña maestra. No se volverá a mostrar y Keyvora no la guarda.",
        )
        Text(
            groups.chunked(4).joinToString("\n") { it.joinToString("-") },
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.titleMedium,
        )
        OutlinedButton(onClick = { c.clipboard.copy(recoveryKey) }, modifier = Modifier.fillMaxWidth()) {
            Text("Copiar (se borra del portapapeles en 30 s)")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = saved, onCheckedChange = { saved = it })
            Text("La he guardado en un lugar seguro")
        }
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it },
            label = { Text("Escribe el último grupo para confirmar") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
        )
        BusyButton("Continuar", busy = false, enabled = saved && typed.trim().equals(last, ignoreCase = true)) {
            c.clipboard.clearIfOurs()
            onDone()
        }
    }
}
