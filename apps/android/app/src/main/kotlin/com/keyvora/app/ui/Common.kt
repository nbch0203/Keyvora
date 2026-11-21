package com.keyvora.app.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.view.WindowManager
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputMethodRequest
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import com.keyvora.app.vault.ThemeMode
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.keyvora.app.AppContainer
import com.keyvora.app.core.CoreException
import com.keyvora.app.security.MasterPasswordPolicy
import com.keyvora.app.sync.RemoteErrorCode
import com.keyvora.app.sync.SyncEngine

val LocalAppContainer = staticCompositionLocalOf<AppContainer> { error("AppContainer not provided") }

@Composable
inline fun <reified VM : ViewModel> appViewModel(key: String? = null, crossinline create: (AppContainer) -> VM): VM {
    val container = LocalAppContainer.current
    return viewModel(key = key, factory = viewModelFactory { initializer { create(container) } })
}

/**
 * FLAG_SECURE: no screenshots, no content in Recents (T17). Also tapjacking protection, so that another app's overlay
 * cannot trick the user into tapping «Asociar y continuar», «Rellenar en …» or «Guardar»:
 * - API 31+: other apps' overlays are hidden while a Keyvora window is shown (HIDE_OVERLAY_WINDOWS), and the system
 *   already drops touches that pass through untrusted overlays.
 * - API 26–30: touches are ignored while another visible window obscures ours.
 */
fun Activity.applySecureWindow() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        window.setHideOverlayWindows(true)
    } else {
        window.decorView.filterTouchesWhenObscured = true
    }
    if (com.keyvora.app.BuildConfig.ALLOW_SCREENSHOTS) return // local UI-review builds only (build.gradle.kts)
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
    CoreException.VALIDATION -> when (detail) {
        "masterPassword" -> MasterPasswordPolicy.message(MasterPasswordPolicy.Problem.TOO_SHORT)
        "masterWeak" -> "Esa contraseña maestra es demasiado débil. Usa una frase de varias palabras poco comunes " +
            "(16 caracteres o más)."
        "masterReused" -> "Ya usaste esa contraseña maestra. Elige una que no hayas usado antes."
        else -> "Datos no válidos" + (detail?.let { " ($it)" } ?: "") + "."
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
    ERR_BIOMETRIC_UNAVAILABLE -> "La biometría no está disponible ahora. Usa tu contraseña maestra."
    ERR_IO -> "No se pudo leer o escribir el archivo."
    else -> "Error inesperado ($code)."
}

const val ERR_BIOMETRIC_INVALIDATED = "BIOMETRIC_INVALIDATED"
const val ERR_BIOMETRIC_UNAVAILABLE = "BIOMETRIC_UNAVAILABLE"
const val ERR_IO = "IO_ERROR"

fun Throwable.errorCode(): String = when (this) {
    is CoreException -> code
    is com.keyvora.app.sync.RemoteException -> code.name
    is java.io.IOException -> ERR_IO
    else -> javaClass.simpleName
}

// ------------------------------------------------------------------------------------------------ theme

// Brand palette (navy of the launcher icon + teal accent), tuned for Material 3 contrast in light and dark.
private val LightColors = lightColorScheme(
    primary = Color(0xFF2B5C8F), onPrimary = Color.White,
    primaryContainer = Color(0xFFD3E4FF), onPrimaryContainer = Color(0xFF001C38),
    secondary = Color(0xFF535F70), onSecondary = Color.White,
    secondaryContainer = Color(0xFFD7E3F7), onSecondaryContainer = Color(0xFF101C2B),
    tertiary = Color(0xFF00696D), onTertiary = Color.White,
    tertiaryContainer = Color(0xFFA0EFF2), onTertiaryContainer = Color(0xFF002021),
    error = Color(0xFFBA1A1A), onError = Color.White,
    errorContainer = Color(0xFFFFDAD6), onErrorContainer = Color(0xFF410002),
    background = Color(0xFFF8F9FF), onBackground = Color(0xFF191C20),
    surface = Color(0xFFF8F9FF), onSurface = Color(0xFF191C20),
    surfaceVariant = Color(0xFFDFE2EB), onSurfaceVariant = Color(0xFF43474E),
    outline = Color(0xFF73777F), outlineVariant = Color(0xFFC3C6CF),
    surfaceContainerLowest = Color.White, surfaceContainerLow = Color(0xFFF2F3FA),
    surfaceContainer = Color(0xFFECEEF4), surfaceContainerHigh = Color(0xFFE6E8EE),
    surfaceContainerHighest = Color(0xFFE1E2E8),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFA1C9FF), onPrimary = Color(0xFF00315B),
    primaryContainer = Color(0xFF164777), onPrimaryContainer = Color(0xFFD3E4FF),
    secondary = Color(0xFFBBC7DB), onSecondary = Color(0xFF253140),
    secondaryContainer = Color(0xFF3B4858), onSecondaryContainer = Color(0xFFD7E3F7),
    tertiary = Color(0xFF83D3D7), onTertiary = Color(0xFF003739),
    tertiaryContainer = Color(0xFF004F52), onTertiaryContainer = Color(0xFFA0EFF2),
    error = Color(0xFFFFB4AB), onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A), onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF111418), onBackground = Color(0xFFE1E2E8),
    surface = Color(0xFF111418), onSurface = Color(0xFFE1E2E8),
    surfaceVariant = Color(0xFF43474E), onSurfaceVariant = Color(0xFFC3C6CF),
    outline = Color(0xFF8D9199), outlineVariant = Color(0xFF43474E),
    surfaceContainerLowest = Color(0xFF0C0E13), surfaceContainerLow = Color(0xFF191C20),
    surfaceContainer = Color(0xFF1D2024), surfaceContainerHigh = Color(0xFF272A2F),
    surfaceContainerHighest = Color(0xFF32353A),
)

@Composable
fun KeyvoraTheme(content: @Composable () -> Unit) {
    val app = LocalContext.current.applicationContext as? com.keyvora.app.KeyvoraApp
    val mode by (app?.container?.themeMode ?: remember { kotlinx.coroutines.flow.MutableStateFlow(ThemeMode.SYSTEM) }).collectAsState()
    val dark = when (mode) {
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }
    // Status / navigation bar icons follow the app theme (which may differ from the system one).
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = view.context.findFragmentActivity()?.window ?: return@SideEffect
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !dark
                isAppearanceLightNavigationBars = !dark
            }
        }
    }
    MaterialTheme(colorScheme = if (dark) DarkColors else LightColors) { NoPersonalizedLearning(content) }
}

/**
 * Every text field in Keyvora (titles, usernames, URLs, notes, search…) asks the keyboard not to learn what is typed:
 * otherwise usernames, sites and notes end up in the keyboard's dictionary and its cloud sync (AUDIT AND-10).
 * Password fields already use a password input type, which keyboards never learn from.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
private fun NoPersonalizedLearning(content: @Composable () -> Unit) {
    InterceptPlatformTextInput(
        interceptor = { request, nextHandler ->
            val noLearning = object : PlatformTextInputMethodRequest {
                override fun createInputConnection(outAttributes: EditorInfo): InputConnection {
                    val connection = request.createInputConnection(outAttributes)
                    outAttributes.imeOptions = outAttributes.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                    return connection
                }
            }
            nextHandler.startInputMethod(noLearning)
        },
        content = content,
    )
}

// ------------------------------------------------------------------------------------------------ icons

/** The few icons not in material-icons-core (Material Design icons, Apache 2.0), without the extended artifact. */
object KvIcons {
    private fun icon(name: String, vararg paths: String): ImageVector =
        ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).apply {
            paths.forEach { addPath(addPathNodes(it), fill = SolidColor(Color.Black)) }
        }.build()

    val Visibility = icon(
        "Visibility",
        "M12,4.5C7,4.5 2.73,7.61 1,12c1.73,4.39 6,7.5 11,7.5s9.27,-3.11 11,-7.5c-1.73,-4.39 -6,-7.5 -11,-7.5zM12,17c-2.76,0 -5,-2.24 -5,-5s2.24,-5 5,-5 5,2.24 5,5 -2.24,5 -5,5zM12,9c-1.66,0 -3,1.34 -3,3s1.34,3 3,3 3,-1.34 3,-3 -1.34,-3 -3,-3z",
    )
    val VisibilityOff = icon(
        "VisibilityOff",
        "M12,7c2.76,0 5,2.24 5,5 0,0.65 -0.13,1.26 -0.36,1.83l2.92,2.92c1.51,-1.26 2.7,-2.89 3.43,-4.75 -1.73,-4.39 -6,-7.5 -11,-7.5 -1.4,0 -2.74,0.25 -3.98,0.7l2.16,2.16C10.74,7.13 11.35,7 12,7zM2,4.27l2.28,2.28 0.46,0.46C3.08,8.3 1.78,10.02 1,12c1.73,4.39 6,7.5 11,7.5 1.55,0 3.03,-0.3 4.38,-0.84l0.42,0.42L19.73,22 21,20.73 3.27,3 2,4.27zM7.53,9.8l1.55,1.55c-0.05,0.21 -0.08,0.43 -0.08,0.65 0,1.66 1.34,3 3,3 0.22,0 0.44,-0.03 0.65,-0.08l1.55,1.55c-0.67,0.33 -1.41,0.53 -2.2,0.53 -2.76,0 -5,-2.24 -5,-5 0,-0.79 0.2,-1.53 0.53,-2.2zM11.84,9.02l3.15,3.15 0.02,-0.16c0,-1.66 -1.34,-3 -3,-3l-0.17,0.01z",
    )
    val Copy = icon(
        "ContentCopy",
        "M16,1L4,1c-1.1,0 -2,0.9 -2,2v14h2L4,3h12L16,1zM19,5L8,5c-1.1,0 -2,0.9 -2,2v14c0,1.1 0.9,2 2,2h11c1.1,0 2,-0.9 2,-2L21,7c0,-1.1 -0.9,-2 -2,-2zM19,21L8,21L8,7h11v14z",
    )
    val Key = icon(
        "VpnKey",
        "M12.65,10C11.83,7.67 9.61,6 7,6c-3.31,0 -6,2.69 -6,6s2.69,6 6,6c2.61,0 4.83,-1.67 5.65,-4H17v4h4v-4h2v-4H12.65zM7,14c-1.1,0 -2,-0.9 -2,-2s0.9,-2 2,-2 2,0.9 2,2 -0.9,2 -2,2z",
    )
    val Shield = icon("Shield", "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5l-9,-4z")
    val Cloud = icon(
        "Cloud",
        "M19.35,10.04C18.67,6.59 15.64,4 12,4 9.11,4 6.6,5.64 5.35,8.04 2.34,8.36 0,10.91 0,14c0,3.31 2.69,6 6,6h13c2.76,0 5,-2.24 5,-5 0,-2.64 -2.05,-4.78 -4.65,-4.96z",
    )
    val Link = icon(
        "Link",
        "M3.9,12c0,-1.71 1.39,-3.1 3.1,-3.1h4V7H7c-2.76,0 -5,2.24 -5,5s2.24,5 5,5h4v-1.9H7c-1.71,0 -3.1,-1.39 -3.1,-3.1zM8,13h8v-2H8v2zM17,7h-4v1.9h4c1.71,0 3.1,1.39 3.1,3.1s-1.39,3.1 -3.1,3.1h-4V17h4c2.76,0 5,-2.24 5,-5s-2.24,-5 -5,-5z",
    )
    val Apps = icon(
        "Apps",
        "M4,8h4V4H4v4zM10,20h4v-4h-4v4zM4,20h4v-4H4v4zM4,14h4v-4H4v4zM10,14h4v-4h-4v4zM16,4v4h4V4h-4zM10,8h4V4h-4v4zM16,14h4v-4h-4v4zM16,20h4v-4h-4v4z",
    )
    val Download = icon("Download", "M19,9h-4V3H9v6H5l7,7 7,-7zM5,18v2h14v-2H5z")
    val Upload = icon("Upload", "M9,16h6v-6h4l-7,-7 -7,7h4zM5,18h14v2H5z")
    val Notes = icon("Notes", "M3,18h12v-2H3v2zM3,6v2h18V6H3zM3,13h18v-2H3v2z")
    val Timer = icon(
        "Timer",
        "M15,1H9v2h6V1zM11,14h2V8h-2v6zM19.03,7.39l1.42,-1.42c-0.43,-0.51 -0.9,-0.99 -1.41,-1.41l-1.42,1.42C16.07,4.74 14.12,4 12,4c-4.97,0 -9,4.03 -9,9s4.02,9 9,9 9,-4.03 9,-9c0,-2.12 -0.74,-4.07 -1.97,-5.61zM12,20c-3.87,0 -7,-3.13 -7,-7s3.13,-7 7,-7 7,3.13 7,7 -3.13,7 -7,7z",
    )
    /** Half-filled circle (Contrast): appearance / dark mode. */
    val Contrast = icon(
        "Contrast",
        "M12,22c5.52,0 10,-4.48 10,-10S17.52,2 12,2 2,6.48 2,12s4.48,10 10,10zM13,4.07c3.94,0.49 7,3.85 7,7.93s-3.05,7.44 -7,7.93V4.07z",
    )
    val History = icon(
        "History",
        "M13,3c-4.97,0 -9,4.03 -9,9H1l3.89,3.89 0.07,0.14L9,12H6c0,-3.87 3.13,-7 7,-7s7,3.13 7,7 -3.13,7 -7,7c-1.93,0 -3.68,-0.79 -4.94,-2.06l-1.42,1.42C8.27,19.99 10.51,21 13,21c4.97,0 9,-4.03 9,-9s-4.03,-9 -9,-9zM12,8v5l4.28,2.54 0.72,-1.21 -3.5,-2.08V8H12z",
    )

    /** Stylised fingerprint: concentric strokes (stroked, not filled). */
    val Fingerprint: ImageVector = ImageVector.Builder("Fingerprint", 24.dp, 24.dp, 24f, 24f).apply {
        listOf(
            "M5,9.5C6.3,6.3 9,4.5 12,4.5s5.7,1.8 7,5",
            "M7.5,19C6.6,17.4 6,15.5 6,13.5c0,-3.3 2.7,-6 6,-6s6,2.7 6,6c0,1 -0.2,2 -0.5,2.8",
            "M10.5,20.5C9.6,18.6 9,16.4 9,14c0,-1.7 1.3,-3 3,-3s3,1.3 3,3c0,1.9 0.4,3.7 1.2,5.3",
            "M12,14c0,2.6 0.7,5 2,7",
        ).forEach {
            addPath(addPathNodes(it), stroke = SolidColor(Color.Black), strokeLineWidth = 1.8f, strokeLineCap = StrokeCap.Round)
        }
    }.build()
}

// ------------------------------------------------------------------------------------------------ widgets

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScreenScaffold(
    title: String,
    onBack: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {},
    floating: @Composable () -> Unit = {},
    snackbar: SnackbarHostState? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = {
                    if (onBack != null) {
                        IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Atrás") }
                    }
                },
                actions = { actions() },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface),
            )
        },
        floatingActionButton = floating,
        snackbarHost = { if (snackbar != null) SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
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
    leadingIcon: ImageVector? = null,
    extraAction: (@Composable () -> Unit)? = null,
    onDone: (() -> Unit)? = null,
) {
    var visible by rememberSaveable { mutableStateOf(false) }
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            autoCorrectEnabled = false,
            imeAction = if (onDone != null) ImeAction.Done else ImeAction.Default,
        ),
        keyboardActions = KeyboardActions(onDone = { onDone?.invoke() }),
        textStyle = if (monospace) MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyLarge,
        leadingIcon = leadingIcon?.let { { Icon(it, contentDescription = null) } },
        trailingIcon = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                extraAction?.invoke()
                IconButton(onClick = { visible = !visible }) {
                    Icon(if (visible) KvIcons.VisibilityOff else KvIcons.Visibility, contentDescription = if (visible) "Ocultar" else "Mostrar")
                }
            }
        },
    )
}

/** Plain text field with the app's shape. */
@Composable
fun KvTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    leadingIcon: ImageVector? = null,
    singleLine: Boolean = true,
    minLines: Int = 1,
    supporting: String? = null,
    keyboardType: KeyboardType = KeyboardType.Text,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = singleLine,
        minLines = minLines,
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        leadingIcon = leadingIcon?.let { { Icon(it, contentDescription = null) } },
        supportingText = supporting?.let { { Text(it) } },
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType, autoCorrectEnabled = false),
    )
}

@Composable
fun ErrorText(code: String?, detail: String? = null) {
    if (code != null) Notice(errorMessage(code, detail), NoticeKind.ERROR)
}

@Composable
fun BusyButton(text: String, busy: Boolean, modifier: Modifier = Modifier, enabled: Boolean = true, icon: ImageVector? = null, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = enabled && !busy, modifier = modifier.fillMaxWidth().heightIn(min = 52.dp)) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
            Spacer(Modifier.width(10.dp))
            Text("Procesando…")
        } else {
            if (icon != null) {
                Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
            }
            Text(text)
        }
    }
}

/**
 * [AlertDialog] with the same tapjacking protection as the activities (AUDIT AND-8): a dialog has its own window, so on
 * API 26–30 it must ignore touches itself while another app's window covers it. On API 31+ the activity window,
 * still shown behind the dialog, already hides other apps' overlays.
 */
@Composable
fun SecureAlertDialog(
    onDismissRequest: () -> Unit,
    confirmButton: @Composable () -> Unit,
    dismissButton: (@Composable () -> Unit)? = null,
    title: (@Composable () -> Unit)? = null,
    text: (@Composable () -> Unit)? = null,
) {
    AlertDialog(
        onDismissRequest = onDismissRequest,
        confirmButton = confirmButton,
        dismissButton = dismissButton,
        title = title,
        text = {
            FilterObscuredTouches()
            text?.invoke()
        },
    )
}

@Composable
private fun FilterObscuredTouches() {
    val view = LocalView.current
    DisposableEffect(view) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) view.rootView.filterTouchesWhenObscured = true
        onDispose { }
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
    SecureAlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirm) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}

/** Round brand mark (key on the primary container), used on the welcome and unlock screens. */
@Composable
fun BrandMark(size: Dp = 72.dp) {
    Box(
        Modifier.size(size).clip(CircleShape).background(MaterialTheme.colorScheme.primaryContainer),
        contentAlignment = Alignment.Center,
    ) {
        Icon(KvIcons.Key, contentDescription = null, tint = MaterialTheme.colorScheme.onPrimaryContainer, modifier = Modifier.size(size * 0.5f))
    }
}

/** Initial of [text] in a colored circle (stable color per title). */
@Composable
fun Monogram(text: String, size: Dp = 42.dp) {
    val cs = MaterialTheme.colorScheme
    val palette = listOf(
        cs.primaryContainer to cs.onPrimaryContainer,
        cs.tertiaryContainer to cs.onTertiaryContainer,
        cs.secondaryContainer to cs.onSecondaryContainer,
    )
    val (bg, fg) = palette[Math.floorMod(text.lowercase().hashCode(), palette.size)]
    val initial = text.firstOrNull { it.isLetterOrDigit() }?.uppercaseChar()?.toString() ?: "•"
    Box(Modifier.size(size).clip(CircleShape).background(bg), contentAlignment = Alignment.Center) {
        Text(initial, color = fg, fontWeight = FontWeight.SemiBold, fontSize = (size.value * 0.42f).sp)
    }
}

/** Card grouping related content, with an optional header. */
@Composable
fun SectionCard(title: String? = null, icon: ImageVector? = null, content: @Composable ColumnScope.() -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(vertical = 8.dp)) {
            if (title != null) {
                Row(Modifier.padding(start = 20.dp, end = 20.dp, top = 8.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    if (icon != null) {
                        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(10.dp))
                    }
                    Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
                }
            }
            content()
        }
    }
}

/** Padding used for free text inside a [SectionCard]. */
val CardTextPadding = Modifier.padding(horizontal = 20.dp, vertical = 6.dp)

/** Tappable row inside a [SectionCard]: icon, title, optional subtitle and chevron (or a custom trailing). */
@Composable
fun SettingsRow(
    icon: ImageVector?,
    title: String,
    subtitle: String? = null,
    enabled: Boolean = true,
    danger: Boolean = false,
    trailing: (@Composable () -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    val color = when {
        !enabled -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
        danger -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurface
    }
    Row(
        Modifier
            .fillMaxWidth()
            .let { if (onClick != null) it.clickable(enabled = enabled, onClick = onClick) else it }
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, tint = if (danger) color else MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(18.dp))
        }
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = color)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        when {
            trailing != null -> trailing()
            onClick != null -> Icon(
                Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

enum class NoticeKind { INFO, WARNING, ERROR, SUCCESS }

/** Tonal message box with an icon (replaces bare red/blue text). */
@Composable
fun Notice(text: String, kind: NoticeKind = NoticeKind.INFO, action: (@Composable () -> Unit)? = null) {
    val cs = MaterialTheme.colorScheme
    val (bg, fg, icon) = when (kind) {
        NoticeKind.INFO -> Triple(cs.secondaryContainer, cs.onSecondaryContainer, Icons.Filled.Info)
        NoticeKind.WARNING -> if (cs.background.luminance() < 0.5f) {
            Triple(Color(0xFF4A3B00), Color(0xFFFFE08A), Icons.Filled.Warning)
        } else {
            Triple(Color(0xFFFFE9B0), Color(0xFF3A2A00), Icons.Filled.Warning)
        }
        NoticeKind.ERROR -> Triple(cs.errorContainer, cs.onErrorContainer, Icons.Filled.Warning)
        NoticeKind.SUCCESS -> Triple(cs.primaryContainer, cs.onPrimaryContainer, Icons.Filled.CheckCircle)
    }
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = bg, contentColor = fg)) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.Top) {
                Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(12.dp))
                Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            }
            if (action != null) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) { action() }
            }
        }
    }
}

/** Strength bar for a new master password (same thresholds as [MasterPasswordPolicy]). */
@Composable
fun StrengthMeter(password: String) {
    val len = MasterPasswordPolicy.length(password)
    val cs = MaterialTheme.colorScheme
    val (progress, color) = when {
        password.isEmpty() -> 0f to cs.outline
        len < MasterPasswordPolicy.MIN_LENGTH -> (0.15f + 0.35f * len / MasterPasswordPolicy.MIN_LENGTH) to cs.error
        len < MasterPasswordPolicy.RECOMMENDED_LENGTH -> 0.65f to cs.tertiary
        else -> 1f to cs.primary
    }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(4.dp)),
            color = color,
            trackColor = cs.surfaceContainerHighest,
            drawStopIndicator = {},
        )
        Text(MasterPasswordPolicy.hint(password), style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
    }
}

@Composable
fun rememberBoolean(initial: Boolean = false) = remember { mutableStateOf(initial) }

/** Formats an ISO timestamp from the core (`YYYY-MM-DDTHH:MM:SS.sssZ`) for display. */
fun shortDate(iso: String): String = iso.take(16).replace('T', ' ')

/** Short label for an entry URL: host without `www.`, or the package of an `androidapp://` entry. */
fun displayHostOf(url: String): String {
    if (url.startsWith("androidapp://")) return url.removePrefix("androidapp://")
    val host = runCatching { java.net.URI(if ("://" in url) url else "https://$url").host }.getOrNull()
    return (host ?: url).removePrefix("www.")
}
