package com.keyvora.app.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.view.WindowManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.keyvora.app.AppContainer
import com.keyvora.app.core.CoreException
import com.keyvora.app.sync.RemoteErrorCode
import com.keyvora.app.sync.SyncEngine

val LocalAppContainer = staticCompositionLocalOf<AppContainer> { error("AppContainer not provided") }

@Composable
inline fun <reified VM : ViewModel> appViewModel(key: String? = null, crossinline create: (AppContainer) -> VM): VM {
    val container = LocalAppContainer.current
    return viewModel(key = key, factory = viewModelFactory { initializer { create(container) } })
}

/** FLAG_SECURE: no screenshots, no content in Recents (T17). */
fun Activity.applySecureWindow() {
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) setRecentsScreenshotEnabled(false)
}

fun Context.findFragmentActivity(): FragmentActivity? {
    var c: Context? = this
    while (c is ContextWrapper) {
        if (c is FragmentActivity) return c
        c = c.baseContext
    }
    return null
}

/** Spanish message for an error code (core §1.2, transport §6, app-level). Never includes secrets. */
fun errorMessage(code: String?, detail: String? = null): String = when (code) {
    null -> ""
    CoreException.INVALID_CREDENTIALS -> "Contraseña o clave incorrecta."
    CoreException.INVALID_RECOVERY_KEY -> "La clave de recuperación tiene un error de tecleo. Revísala."
    CoreException.INVALID_FORMAT -> "El archivo no es una bóveda de Keyvora válida."
    CoreException.UNSUPPORTED_VERSION -> "Versión de bóveda no compatible. Actualiza la aplicación."
    CoreException.PARAMS_OUT_OF_BOUNDS -> "Parámetros de cifrado fuera de los límites permitidos."
    CoreException.INTEGRITY_ERROR -> "La bóveda está dañada o ha sido manipulada. No se ha modificado nada."
    CoreException.VAULT_MISMATCH -> "La copia pertenece a otra bóveda."
    CoreException.NOT_FOUND -> "No encontrado."
    CoreException.VALIDATION -> if (detail == "masterPassword") {
        com.keyvora.app.security.MasterPasswordPolicy.message(com.keyvora.app.security.MasterPasswordPolicy.Problem.TOO_SHORT)
    } else {
        "Datos no válidos" + (detail?.let { " ($it)" } ?: "") + "."
    }
    CoreException.KEYRING_CHANGED -> "La contraseña maestra o la clave de cifrado cambiaron en otro dispositivo. " +
        "Introduce la contraseña maestra actual para continuar."
    CoreException.LOCKED -> "La bóveda está bloqueada."
    CoreException.CRYPTO -> "Error criptográfico interno."
    CoreException.CORE_NOT_BUILT -> "Esta compilación no incluye el núcleo criptográfico (ver README)."
    RemoteErrorCode.NETWORK.name -> "Sin conexión con Google Drive. Se reintentará."
    RemoteErrorCode.AUTH_REQUIRED.name -> "Vuelve a conectar tu cuenta de Google."
    RemoteErrorCode.RATE_LIMITED.name -> "Google Drive limita las peticiones. Se reintentará."
    RemoteErrorCode.REMOTE_ERROR.name -> "Error de Google Drive."
    SyncEngine.CONFLICT_RETRY_EXHAUSTED -> "Demasiados cambios simultáneos. Tus datos siguen a salvo; se reintentará."
    ERR_BIOMETRIC_INVALIDATED -> "La biometría del dispositivo cambió. Usa tu contraseña maestra y vuelve a activarla."
    ERR_IO -> "No se pudo leer o escribir el archivo."
    else -> "Error inesperado ($code)."
}

const val ERR_BIOMETRIC_INVALIDATED = "BIOMETRIC_INVALIDATED"
const val ERR_IO = "IO_ERROR"

fun Throwable.errorCode(): String = when (this) {
    is CoreException -> code
    is com.keyvora.app.sync.RemoteException -> code.name
    is java.io.IOException -> ERR_IO
    else -> javaClass.simpleName
}

// ------------------------------------------------------------------------------------------------ theme

@Composable
fun KeyvoraTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val ctx = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

// ------------------------------------------------------------------------------------------------ widgets

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScreenScaffold(
    title: String,
    onBack: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {},
    floating: @Composable () -> Unit = {},
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    if (onBack != null) {
                        IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Atrás") }
                    }
                },
                actions = { actions() },
            )
        },
        floatingActionButton = floating,
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            content = content,
        )
    }
}

@Composable
fun SecretField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    monospace: Boolean = false,
) {
    var visible by rememberSaveable { mutableStateOf(false) }
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        modifier = modifier.fillMaxWidth(),
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
        textStyle = if (monospace) MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyLarge,
        trailingIcon = {
            TextButton(onClick = { visible = !visible }) { Text(if (visible) "Ocultar" else "Mostrar") }
        },
    )
}

@Composable
fun ErrorText(code: String?, detail: String? = null) {
    if (code != null) Text(errorMessage(code, detail), color = MaterialTheme.colorScheme.error)
}

@Composable
fun BusyButton(text: String, busy: Boolean, modifier: Modifier = Modifier, enabled: Boolean = true, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = enabled && !busy, modifier = modifier.fillMaxWidth()) {
        if (busy) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text("Procesando…")
            }
        } else {
            Text(text)
        }
    }
}

@Composable
fun ConfirmDialog(
    title: String,
    text: String,
    confirm: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirm) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}

@Composable
fun rememberBoolean(initial: Boolean = false) = remember { mutableStateOf(initial) }

/** Formats an ISO timestamp from the core (`YYYY-MM-DDTHH:MM:SS.sssZ`) for display. */
fun shortDate(iso: String): String = iso.take(16).replace('T', ' ')
