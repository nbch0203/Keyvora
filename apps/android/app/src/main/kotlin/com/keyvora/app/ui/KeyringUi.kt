package com.keyvora.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.keyvora.app.core.CoreException
import com.keyvora.app.sync.KeyringAdoption
import kotlinx.coroutines.launch

/**
 * ADR-013: newer keys found remotely (sync) or in an imported copy are never adopted silently. Asks for the master
 * password that opens that container, adopts its keys (merging local data) and reports weaker KDF parameters /
 * biometrics that need re-enabling.
 */
@Composable
fun KeyringAdoptionHost() {
    val c = LocalAppContainer.current
    val pending by c.keyring.pending.collectAsStateWithLifecycle()
    var outcome by remember { mutableStateOf<String?>(null) }
    val p = pending
    if (p != null) {
        KeyringPasswordDialog(p.source, onDismiss = c.keyring::dismiss) { result -> outcome = result }
    }
    outcome?.let { msg ->
        SecureAlertDialog(
            onDismissRequest = { outcome = null },
            title = { Text("Claves actualizadas") },
            text = { Text(msg) },
            confirmButton = { TextButton(onClick = { outcome = null }) { Text("Entendido") } },
        )
    }
}

@Composable
private fun KeyringPasswordDialog(source: KeyringAdoption.Source, onDismiss: () -> Unit, onDone: (String) -> Unit) {
    val c = LocalAppContainer.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    SecureAlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Se cambiaron las claves de la bóveda") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    if (source == KeyringAdoption.Source.SYNC) {
                        "Otro dispositivo cambió la contraseña maestra o rotó la clave de cifrado. Para seguir " +
                            "sincronizando, introduce la contraseña maestra ACTUAL (la nueva). Hasta entonces no se sube nada."
                    } else {
                        "La copia importada tiene claves más nuevas. Introduce la contraseña maestra de esa copia para fusionarla."
                    },
                )
                SecretField(password, { password = it }, "Contraseña maestra")
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (busy) Text("Comprobando…")
            }
        },
        confirmButton = {
            TextButton(enabled = password.isNotEmpty() && !busy, onClick = {
                busy = true
                error = null
                scope.launch {
                    try {
                        val r = c.keyring.adopt(password)
                        val parts = mutableListOf("Las claves nuevas se adoptaron y tus datos locales se fusionaron.")
                        if (r.report.recoveryKeyChanged) {
                            parts += "La clave de recuperación que se mostró en este dispositivo ya no es válida: ahora vale la " +
                                "generada en el otro dispositivo. Si no la tienes guardada, usa «Generar nueva clave de recuperación» en Ajustes."
                        }
                        if (r.report.kdfWeakened) {
                            parts += "Atención: la nueva contraseña usa parámetros de derivación más débiles que antes. " +
                                "Si no lo hiciste tú, cambia la contraseña maestra en Ajustes."
                        }
                        if (r.dataKeyChanged && c.settings.biometricNeedsReenable) {
                            parts += "La clave de cifrado cambió: vuelve a activar la biometría en Ajustes."
                        }
                        onDone(parts.joinToString("\n\n"))
                    } catch (e: Exception) {
                        error = if ((e as? CoreException)?.code == CoreException.INVALID_CREDENTIALS) {
                            "Esa contraseña no abre la bóveda actualizada."
                        } else {
                            errorMessage(e.errorCode())
                        }
                    } finally {
                        busy = false
                    }
                }
            }) { Text("Continuar") }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("Ahora no") } },
    )
}
