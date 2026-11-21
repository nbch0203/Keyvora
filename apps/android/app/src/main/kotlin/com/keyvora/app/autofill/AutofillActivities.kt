package com.keyvora.app.autofill

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.os.Parcelable
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.core.content.IntentCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.keyvora.app.AppContainer
import com.keyvora.app.KeyvoraApp
import com.keyvora.app.core.CredentialMatch
import com.keyvora.app.core.EntrySummary
import com.keyvora.app.core.GeneratorOptions
import com.keyvora.app.core.MatchLevel
import com.keyvora.app.ui.BusyButton
import com.keyvora.app.ui.GeneratorCard
import com.keyvora.app.ui.KvTextField
import com.keyvora.app.ui.Monogram
import com.keyvora.app.ui.Notice
import com.keyvora.app.ui.NoticeKind
import com.keyvora.app.ui.displayHostOf
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.TextButton
import androidx.compose.ui.unit.dp
import com.keyvora.app.ui.KeyvoraTheme
import com.keyvora.app.ui.LocalAppContainer
import com.keyvora.app.ui.ScreenScaffold
import com.keyvora.app.ui.SecretField
import com.keyvora.app.ui.UnlockPanel
import com.keyvora.app.ui.UnlockViewModel
import com.keyvora.app.ui.appViewModel
import com.keyvora.app.ui.applySecureWindow
import com.keyvora.app.ui.errorCode
import com.keyvora.app.ui.errorMessage
import com.keyvora.app.vault.VaultManager
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope
import android.view.autofill.AutofillId

/**
 * Launched by the autofill framework (PendingIntent from [AutofillResponses.authSender]):
 * - MODE_UNLOCK: vault locked → unlock, then return a FillResponse built from the core's matches.
 * - MODE_CONFIRM: a `sameSite` match → show the real host and ask for explicit confirmation, then return the Dataset.
 * - MODE_GENERATE: generate a password, save it as a new entry for the target, then return a Dataset that fills it.
 * The structure is re-parsed and the target must equal the one the service computed.
 */
class AutofillAuthActivity : FragmentActivity() {
    private val container: AppContainer by lazy { (application as KeyvoraApp).container }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        applySecureWindow()
        container.autoLock.lockIfExpired() // the deadline may have passed while the process was frozen (AND-SEC-2)
        setResult(Activity.RESULT_CANCELED)
        val mode = intent.getStringExtra(EXTRA_MODE) ?: MODE_UNLOCK
        if (mode == MODE_WARN) {
            val reason = RefusalReason.entries.firstOrNull { it.name == intent.getStringExtra(EXTRA_REASON) } ?: return finish()
            val pkg = (TargetExtras.get(intent) as? FillTarget.App)?.packageName.orEmpty()
            setContent { KeyvoraTheme { WarningContent(AutofillTrust.refusalMessage(reason, pkg)) } }
            return
        }
        val structure = IntentCompat.getParcelableExtra(intent, AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        val expected = TargetExtras.get(intent)
        if (structure == null || expected is FillTarget.None) return finish()
        val pkg = structure.activityComponent?.packageName.orEmpty()
        val caller = container.callerResolver.resolve(pkg)
        val form = AssistStructureMapper.parse(structure, caller, withValues = mode == MODE_GENERATE)
        // Re-derive trust here; never rely on what the service computed.
        val decision = AutofillTrust.decide(form, caller, packageName, container.trustPins)
        val (target, pending) = when (decision) {
            is TrustDecision.Trusted -> decision.target to null
            is TrustDecision.NeedsConfirmation -> decision.target to decision
            is TrustDecision.Refused -> return finish()
        }
        if (target != expected || form.isEmpty) return finish()
        val entryId = intent.getStringExtra(EXTRA_ENTRY_ID)

        setContent {
            KeyvoraTheme {
                CompositionLocalProvider(LocalAppContainer provides container) {
                    AuthContent(mode, entryId, form, target, pending)
                }
            }
        }
    }

    private fun deliver(result: Parcelable) {
        setResult(Activity.RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, result))
        finish()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        container.autoLock.onUserInteraction()
    }

    @Composable
    private fun WarningContent(message: String) {
        ScreenScaffold("Keyvora · Aviso de seguridad") {
            Text(message, color = MaterialTheme.colorScheme.error)
            OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cerrar") }
        }
    }

    @Composable
    private fun AuthContent(
        mode: String,
        entryId: String?,
        form: ParsedForm<AutofillId>,
        target: FillTarget,
        pending: TrustDecision.NeedsConfirmation?,
    ) {
        val status by container.vault.status.collectAsStateWithLifecycle()
        var trusted by remember { mutableStateOf(pending == null) }
        var generating by remember { mutableStateOf(mode == MODE_GENERATE) }
        var picking by remember { mutableStateOf(mode == MODE_PICK) }
        val host = target.displayHost()
        ScreenScaffold("Keyvora · Autorrelleno") {
            when (status) {
                VaultManager.Status.NO_VAULT -> {
                    Text("No hay ninguna bóveda en este dispositivo.")
                    OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cerrar") }
                }
                VaultManager.Status.LOCKED -> {
                    val vm = appViewModel { UnlockViewModel(it) }
                    UnlockPanel(vm, "Desbloquea Keyvora para rellenar en $host")
                    OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cancelar") }
                }
                VaultManager.Status.UNLOCKED -> when {
                    // A new app is pinned by saving the generated entry (same rule as the save flow, CONTRACTS §4.1).
                    generating && (trusted || pending?.kind == PinKind.APP) ->
                        GenerateContent(form, target, pending?.takeIf { !trusted })
                    picking && (trusted || pending?.kind == PinKind.APP) ->
                        PickContent(form, target, pending?.takeIf { !trusted })
                    !trusted && pending != null ->
                        TrustConfirmContent(pending, form, onGenerate = { generating = true }, onPick = { picking = true }) { trusted = true }
                    mode == MODE_CONFIRM && entryId != null -> ConfirmContent(entryId, form, target)
                    else -> ResponseContent(form, target)
                }
            }
        }
    }

    /**
     * TOFU for native apps (CONTRACTS §4.1): the user explicitly associates the app; its certificate is pinned.
     * Browsers never get here: they are verified against their official certificates ([AutofillTrust.KNOWN_BROWSERS]).
     */
    @Composable
    private fun TrustConfirmContent(
        d: TrustDecision.NeedsConfirmation,
        form: ParsedForm<AutofillId>,
        onGenerate: () -> Unit,
        onPick: () -> Unit,
        onTrusted: () -> Unit,
    ) {
        val pkg = d.caller.packageName
        var appEntries by remember { mutableStateOf<List<String>?>(null) }
        LaunchedEffect(pkg) {
            appEntries = runCatching { container.vault.read { s -> s.findAppMatches(pkg).map { it.entry.title } } }.getOrDefault(emptyList())
        }
        val entries = appEntries
        if (entries == null) {
            Text("Comprobando…")
            return
        }
        if (entries.isEmpty()) {
            Text("No hay ninguna entrada vinculada a la app $pkg.")
            if (AutofillPick.shouldOffer(form, isApp = true, savedMatches = 0)) {
                BusyButton("Elegir una entrada de Keyvora", busy = false) { onPick() }
            }
            if (form.generatedPasswordIds.isNotEmpty()) {
                OutlinedButton(onClick = onGenerate, modifier = Modifier.fillMaxWidth()) { Text("Generar contraseña nueva") }
            }
            OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cerrar") }
            return
        }
        Text("¿Asociar esta app con tus entradas?", style = MaterialTheme.typography.titleMedium)
        Text("App: $pkg")
        Text("Entradas: ${entries.joinToString(", ")}")
        Text("Certificado de firma (SHA-256):\n${certLines(d.caller)}", style = MaterialTheme.typography.bodySmall)
        Text("Se recordará este certificado. Una app con el mismo nombre pero otro certificado no recibirá tus datos.")
        BusyButton("Asociar y continuar", busy = false) {
            container.trustPins.setPin(PinKind.APP, pkg, d.caller.certDigests)
            onTrusted()
        }
        OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cancelar") }
    }

    /**
     * MODE_PICK (native apps only): the user chooses a saved entry; after confirming, `androidapp://<package>` is added
     * to it and the app's certificate is pinned if this is the first association (CONTRACTS §4.1), then it is filled.
     */
    @Composable
    private fun PickContent(form: ParsedForm<AutofillId>, target: FillTarget, pin: TrustDecision.NeedsConfirmation?) {
        val app = target as? FillTarget.App
        // Never on a web page, not even one inside the app's WebView: a site must match by origin (CONTRACTS §4.1).
        if (app == null || form.hasWebContent) {
            LaunchedEffect(Unit) { finish() }
            return
        }
        var query by remember { mutableStateOf("") }
        var entries by remember { mutableStateOf<List<EntrySummary>>(emptyList()) }
        var chosen by remember { mutableStateOf<EntrySummary?>(null) }
        var busy by remember { mutableStateOf(false) }
        var error by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(query) {
            entries = runCatching { container.vault.listEntries(query) }.getOrDefault(emptyList())
        }
        val c = chosen
        if (c == null) {
            Text("¿Qué cuenta quieres usar en esta app?", style = MaterialTheme.typography.titleMedium)
            Text(app.packageName, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            KvTextField(query, { query = it }, "Buscar en tu bóveda", leadingIcon = Icons.Filled.Search)
            if (entries.isEmpty()) Text("No hay entradas.", style = MaterialTheme.typography.bodyMedium)
            entries.take(MAX_PICK).forEach { e ->
                Card(
                    onClick = { chosen = e },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
                ) {
                    Row(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Monogram(e.title)
                        Spacer(Modifier.width(14.dp))
                        Column(Modifier.weight(1f)) {
                            Text(e.title, style = MaterialTheme.typography.titleMedium, maxLines = 1)
                            val sub = listOfNotNull(e.username.takeIf { it.isNotEmpty() }, e.urls.firstOrNull()?.let(::displayHostOf)).joinToString(" · ")
                            if (sub.isNotEmpty()) {
                                Text(sub, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
                            }
                        }
                    }
                }
            }
            OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cancelar") }
            return
        }
        Text("¿Usar «${c.title}» en esta app?", style = MaterialTheme.typography.titleMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Monogram(c.title)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(c.title, style = MaterialTheme.typography.titleMedium)
                if (c.username.isNotEmpty()) Text(c.username, style = MaterialTheme.typography.bodyMedium)
            }
        }
        Text("App: ${app.packageName}", style = MaterialTheme.typography.bodyMedium)
        Notice(
            "Se añadirá androidapp://${app.packageName} a la entrada para rellenarla aquí directamente la próxima vez." +
                if (pin != null) " También se recordará el certificado de firma de la app; otra app con el mismo nombre no recibirá tus datos." else "",
        )
        if (pin != null) {
            Text("Certificado de firma (SHA-256):\n" + certLines(pin.caller), style = MaterialTheme.typography.bodySmall)
        }
        error?.let { Notice(saveErrorMessage(it, app.packageName), NoticeKind.ERROR) }
        BusyButton("Vincular y rellenar", busy) {
            busy = true
            scope.launch {
                try {
                    pin?.let { AutofillStore.confirmPin(container.trustPins, it.kind, it.caller) }
                    AutofillStore.link(container.vault, c.id, "androidapp://${app.packageName}")
                    val entry = container.vault.getEntry(c.id)
                    deliver(AutofillResponses.dataset(this@AutofillAuthActivity, form, entry))
                } catch (e: Exception) {
                    error = e.errorCode()
                    busy = false
                }
            }
        }
        TextButton(onClick = { chosen = null }, modifier = Modifier.fillMaxWidth()) { Text("Elegir otra entrada") }
    }

    /** MODE_GENERATE: new password -> saved as a new entry for [target] first -> then filled (like the extension). */
    @Composable
    private fun GenerateContent(form: ParsedForm<AutofillId>, target: FillTarget, pin: TrustDecision.NeedsConfirmation?) {
        val core = container.core
        fun generate(o: GeneratorOptions) = runCatching { core.generatePassword(o) }.getOrDefault("")
        var options by remember { mutableStateOf(runCatching { core.defaultGeneratorOptions() }.getOrDefault(GeneratorOptions())) }
        var password by remember { mutableStateOf(generate(options)) }
        val entropy = remember(options) { runCatching { core.passwordEntropyBits(options) }.getOrNull() }
        var title by remember { mutableStateOf(target.displayHost()) }
        var username by remember { mutableStateOf(form.usernameValue.orEmpty()) }
        var busy by remember { mutableStateOf(false) }
        var error by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()

        Text("Contraseña nueva para ${target.displayHost()}", style = MaterialTheme.typography.titleMedium)
        SecretField(password, { password = it }, "Contraseña generada", monospace = true)
        GeneratorCard(options, entropy, onOptions = { options = it; password = generate(it) }, onGenerate = { password = generate(options) })
        OutlinedTextField(title, { title = it }, label = { Text("Título") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            username,
            { username = it },
            label = { Text("Usuario o correo (opcional)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        if (pin != null) {
            Text(
                "Primera vez con la app ${pin.caller.packageName}. Al guardar se recordará su certificado de firma " +
                    "(SHA-256):\n" + certLines(pin.caller),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Text("Se guarda primero en Keyvora y después se escribe en el formulario.", style = MaterialTheme.typography.bodySmall)
        error?.let { Text(saveErrorMessage(it, pin?.caller?.packageName.orEmpty()), color = MaterialTheme.colorScheme.error) }
        BusyButton("Guardar y rellenar", busy, enabled = title.isNotBlank() && password.isNotEmpty()) {
            busy = true
            scope.launch {
                try {
                    pin?.let { AutofillStore.confirmPin(container.trustPins, it.kind, it.caller) }
                    val url = AutofillStore.entryUrl(core, target) ?: return@launch finish()
                    AutofillStore.save(container.vault, url, null, title.trim(), username.trim(), password)
                    deliver(AutofillResponses.generatedDataset(this@AutofillAuthActivity, form, username.trim(), password))
                } catch (e: Exception) {
                    error = e.errorCode()
                    busy = false
                }
            }
        }
        OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cancelar") }
    }

    @Composable
    private fun ResponseContent(form: ParsedForm<AutofillId>, target: FillTarget) {
        var empty by remember { mutableStateOf(false) }
        var error by remember { mutableStateOf<String?>(null) }
        LaunchedEffect(Unit) {
            try {
                val response = AutofillResponses.unlocked(this@AutofillAuthActivity, container.vault, form, target)
                if (response != null) deliver(response) else empty = true
            } catch (e: Exception) {
                error = e.errorCode()
            }
        }
        when {
            error != null -> Text(errorMessage(error), color = MaterialTheme.colorScheme.error)
            empty -> Text("No hay credenciales guardadas para ${target.displayHost()}.")
            else -> Text("Buscando credenciales…")
        }
        if (empty || error != null) {
            OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cerrar") }
        }
    }

    @Composable
    private fun ConfirmContent(entryId: String, form: ParsedForm<AutofillId>, target: FillTarget) {
        var match by remember { mutableStateOf<CredentialMatch?>(null) }
        var error by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(entryId) {
            try {
                // Re-check with the core: the entry must still match this page.
                val found = container.vault.read { s ->
                    when (target) {
                        is FillTarget.Web -> s.findMatches(target.pageUrl)
                        is FillTarget.App -> s.findAppMatches(target.packageName)
                        is FillTarget.None -> emptyList()
                    }
                }.firstOrNull { it.entry.id == entryId && it.level != MatchLevel.NONE }
                if (found == null) error = "NOT_FOUND" else match = found
            } catch (e: Exception) {
                error = e.errorCode()
            }
        }
        val m = match
        when {
            error != null -> {
                Text(errorMessage(error), color = MaterialTheme.colorScheme.error)
                OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cerrar") }
            }
            m == null -> Text("Comprobando…")
            target is FillTarget.App -> {
                // Only reached for a web page inside the app (AutofillTrust.isWebContentInApp): the site is unknown.
                Text("¿Rellenar «${m.entry.title}» en esta página?", style = MaterialTheme.typography.titleMedium)
                Text("App: ${target.packageName}", style = MaterialTheme.typography.titleSmall)
                Text(
                    "La app está mostrando una página web y Keyvora no puede comprobar de qué sitio es: puede ser cualquier " +
                        "enlace que hayas abierto dentro de la app. Rellena solo si es el inicio de sesión de la propia app.",
                    color = MaterialTheme.colorScheme.error,
                )
                BusyButton("Rellenar", busy = false) {
                    scope.launch {
                        try {
                            val entry = container.vault.getEntry(m.entry.id)
                            deliver(AutofillResponses.dataset(this@AutofillAuthActivity, form, entry))
                        } catch (e: Exception) {
                            error = e.errorCode()
                        }
                    }
                }
                OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cancelar") }
            }
            else -> {
                Text("¿Rellenar «${m.entry.title}» en este sitio?", style = MaterialTheme.typography.titleMedium)
                Text("Sitio actual: ${m.pageHost}" + if (m.pageIsIdn) " (dominio internacionalizado)" else "", style = MaterialTheme.typography.titleSmall)
                Text("La entrada se guardó para: ${m.matchedUrl}")
                Text(
                    "No es exactamente el mismo sitio, aunque pertenece al mismo dominio. Comprueba que confías en él antes de continuar.",
                    color = MaterialTheme.colorScheme.error,
                )
                BusyButton("Rellenar en ${m.pageHost}", busy = false) {
                    scope.launch {
                        try {
                            val entry = container.vault.getEntry(m.entry.id)
                            deliver(AutofillResponses.dataset(this@AutofillAuthActivity, form, entry))
                        } catch (e: Exception) {
                            error = e.errorCode()
                        }
                    }
                }
                OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cancelar") }
            }
        }
    }

    companion object {
        const val EXTRA_MODE = "keyvora.autofill.mode"
        const val EXTRA_ENTRY_ID = "keyvora.autofill.entryId"
        const val EXTRA_REASON = "keyvora.autofill.reason"
        const val MODE_UNLOCK = "unlock"
        const val MODE_CONFIRM = "confirm"
        const val MODE_WARN = "warn"
        const val MODE_GENERATE = "generate"
        const val MODE_PICK = "pick"
        private const val MAX_PICK = 50
    }
}

/** Save flow requested by the framework: unlock, then create a new entry or update a matching one. */
class AutofillSaveActivity : FragmentActivity() {
    private val container: AppContainer by lazy { (application as KeyvoraApp).container }
    private var pending: PendingSave? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        applySecureWindow()
        container.autoLock.lockIfExpired()
        val token = intent.getStringExtra(EXTRA_TOKEN)
        // Take ownership: held only by this activity from now on.
        pending = container.pendingSaves.peek(token, System.currentTimeMillis())
        container.pendingSaves.remove(token)
        val p = pending ?: return finish()
        setContent {
            KeyvoraTheme {
                CompositionLocalProvider(LocalAppContainer provides container) { SaveContent(p) }
            }
        }
    }

    override fun onDestroy() {
        pending = null
        super.onDestroy()
    }

    @Composable
    private fun SaveContent(p: PendingSave) {
        val status by container.vault.status.collectAsStateWithLifecycle()
        ScreenScaffold("Guardar en Keyvora") {
            when (status) {
                VaultManager.Status.NO_VAULT -> {
                    Text("Crea primero una bóveda en la app Keyvora.")
                    OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cerrar") }
                }
                VaultManager.Status.LOCKED -> {
                    val vm = appViewModel { UnlockViewModel(it) }
                    UnlockPanel(vm, "Desbloquea Keyvora para guardar la contraseña de ${p.target.displayHost()}")
                    OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cancelar") }
                }
                VaultManager.Status.UNLOCKED -> SaveForm(p)
            }
        }
    }

    @Composable
    private fun SaveForm(p: PendingSave) {
        var title by remember { mutableStateOf(p.target.displayHost()) }
        var username by remember { mutableStateOf(p.username) }
        var password by remember { mutableStateOf(p.password) }
        var matches by remember { mutableStateOf<List<CredentialMatch>>(emptyList()) }
        var selected by remember { mutableStateOf<String?>(null) }
        var busy by remember { mutableStateOf(false) }
        var error by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(Unit) {
            try {
                matches = container.vault.read { s ->
                    when (val t = p.target) {
                        is FillTarget.Web -> s.findMatches(t.pageUrl).filter { it.level == MatchLevel.EXACT }
                        is FillTarget.App -> s.findAppMatches(t.packageName)
                        is FillTarget.None -> emptyList()
                    }
                }
                selected = matches.firstOrNull { it.entry.username == p.username }?.entry?.id
            } catch (e: Exception) {
                error = e.errorCode()
            }
        }
        Text("Sitio o app: ${p.target.displayHost()}")
        if (p.pinKind != null) {
            Text(
                "Primera vez con la app ${p.caller.packageName}. Al guardar se recordará su certificado de firma " +
                    "(SHA-256):\n" + certLines(p.caller),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        OutlinedTextField(title, { title = it }, label = { Text("Título") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(username, { username = it }, label = { Text("Usuario") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        SecretField(password, { password = it }, "Contraseña", monospace = true)
        if (matches.isNotEmpty()) {
            Text("¿Crear una entrada nueva o actualizar una existente?", style = MaterialTheme.typography.titleSmall)
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = selected == null, onClick = { selected = null })
                Text("Nueva entrada")
            }
            matches.forEach { m ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = selected == m.entry.id, onClick = { selected = m.entry.id })
                    Text("Actualizar «${m.entry.title}» (${m.entry.username.ifEmpty { "sin usuario" }})")
                }
            }
        }
        error?.let { Text(saveErrorMessage(it, p.caller.packageName), color = MaterialTheme.colorScheme.error) }
        BusyButton("Guardar", busy, enabled = title.isNotBlank() && password.isNotEmpty()) {
            busy = true
            scope.launch {
                try {
                    p.pinKind?.let { AutofillStore.confirmPin(container.trustPins, it, p.caller) }
                    val url = AutofillStore.entryUrl(container.core, p.target) ?: return@launch finish()
                    AutofillStore.save(container.vault, url, selected, title.trim(), username.trim(), password)
                    pending = null
                    finish()
                } catch (e: Exception) {
                    error = e.errorCode()
                    busy = false
                }
            }
        }
        OutlinedButton(onClick = { pending = null; finish() }, modifier = Modifier.fillMaxWidth()) { Text("No guardar") }
    }

    companion object {
        const val EXTRA_TOKEN = "keyvora.save.token"
    }
}

/** A certificate pinned meanwhile with another value surfaces as IllegalStateException (AutofillStore.confirmPin). */
private fun saveErrorMessage(code: String, packageName: String): String =
    if (code == "IllegalStateException") AutofillTrust.refusalMessage(RefusalReason.APP_CERT_MISMATCH, packageName) else errorMessage(code)

private fun certLines(caller: CallerInfo): String =
    caller.certDigests.sorted().joinToString("\n") { AutofillTrust.formatDigest(it) }
