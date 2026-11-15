package com.keyvora.app.autofill

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.os.Parcelable
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
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
import com.keyvora.app.core.EntryInput
import com.keyvora.app.core.MatchLevel
import com.keyvora.app.ui.BusyButton
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
 * The structure is re-parsed and the target must equal the one the service computed.
 */
class AutofillAuthActivity : FragmentActivity() {
    private val container: AppContainer by lazy { (application as KeyvoraApp).container }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applySecureWindow()
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
        val form = AssistStructureMapper.parse(structure, caller)
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
                    !trusted && pending != null -> TrustConfirmContent(pending) { trusted = true }
                    mode == MODE_CONFIRM && entryId != null -> ConfirmContent(entryId, form, target)
                    else -> ResponseContent(form, target)
                }
            }
        }
    }

    /** TOFU (CONTRACTS §4.1): the user explicitly confirms the browser / app; its certificate is pinned. */
    @Composable
    private fun TrustConfirmContent(d: TrustDecision.NeedsConfirmation, onTrusted: () -> Unit) {
        val pkg = d.caller.packageName
        var appEntries by remember { mutableStateOf<List<String>?>(null) }
        LaunchedEffect(pkg) {
            if (d.kind == PinKind.APP) {
                appEntries = runCatching { container.vault.read { s -> s.findAppMatches(pkg).map { it.entry.title } } }.getOrDefault(emptyList())
            }
        }
        val digests = certLines(d.caller)
        if (d.kind == PinKind.BROWSER) {
            Text("¿Confías en este navegador?", style = MaterialTheme.typography.titleMedium)
            Text("Paquete: $pkg")
            Text("Certificado de firma (SHA-256):\n$digests", style = MaterialTheme.typography.bodySmall)
            Text(
                "Keyvora solo usa el dominio que indica un navegador que hayas confirmado. Si su certificado cambia, " +
                    "dejará de rellenar y te avisará.",
            )
        } else {
            val entries = appEntries
            if (entries == null) {
                Text("Comprobando…")
                return
            }
            if (entries.isEmpty()) {
                Text("No hay credenciales guardadas para la app $pkg.")
                OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Cerrar") }
                return
            }
            Text("¿Asociar esta app con tus entradas?", style = MaterialTheme.typography.titleMedium)
            Text("App: $pkg")
            Text("Entradas: ${entries.joinToString(", ")}")
            Text("Certificado de firma (SHA-256):\n$digests", style = MaterialTheme.typography.bodySmall)
            Text("Se recordará este certificado. Una app con el mismo nombre pero otro certificado no recibirá tus datos.")
        }
        BusyButton(if (d.kind == PinKind.BROWSER) "Confiar en este navegador" else "Asociar y continuar", busy = false) {
            container.trustPins.setPin(d.kind, pkg, d.caller.certDigests)
            onTrusted()
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
    }
}

/** Save flow requested by the framework: unlock, then create a new entry or update a matching one. */
class AutofillSaveActivity : FragmentActivity() {
    private val container: AppContainer by lazy { (application as KeyvoraApp).container }
    private var pending: PendingSave? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applySecureWindow()
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
            val what = if (p.pinKind == PinKind.BROWSER) "el navegador" else "la app"
            Text(
                "Primera vez con $what ${p.caller.packageName}. Al guardar se recordará su certificado de firma " +
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
        error?.let {
            val msg = if (it == "IllegalStateException") {
                AutofillTrust.refusalMessage(RefusalReason.APP_CERT_MISMATCH, p.caller.packageName)
            } else {
                errorMessage(it)
            }
            Text(msg, color = MaterialTheme.colorScheme.error)
        }
        BusyButton("Guardar", busy, enabled = title.isNotBlank() && password.isNotEmpty()) {
            busy = true
            scope.launch {
                try {
                    confirmPin(p)
                    save(p.target, selected, title.trim(), username.trim(), password)
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

    /** Pins the caller on first association; refuses if a different certificate was pinned meanwhile. */
    private fun confirmPin(p: PendingSave) {
        val kind = p.pinKind ?: return
        val existing = container.trustPins.pin(kind, p.caller.packageName)
        if (existing != null && !AutofillTrust.certMatches(existing, p.caller.certDigests)) {
            throw IllegalStateException(ERR_PIN_MISMATCH)
        }
        if (existing == null) container.trustPins.setPin(kind, p.caller.packageName, p.caller.certDigests)
    }

    private suspend fun save(target: FillTarget, existingId: String?, title: String, username: String, password: String) {
        val vault = container.vault
        val url = when (target) {
            is FillTarget.Web -> runCatching { container.core.pageOrigin(target.pageUrl) }.getOrNull() ?: target.pageUrl
            is FillTarget.App -> "androidapp://${target.packageName}"
            is FillTarget.None -> return
        }
        val now = vault.now()
        vault.mutate { s ->
            if (existingId == null) {
                s.createEntry(EntryInput(title, username, password, listOf(url), ""), now)
            } else {
                val e = s.getEntry(existingId)
                val urls = if (e.urls.contains(url)) e.urls else e.urls + url
                s.updateEntry(existingId, EntryInput(e.title, username, password, urls, e.notes), now)
            }
        }
    }

    companion object {
        const val EXTRA_TOKEN = "keyvora.save.token"
        private const val ERR_PIN_MISMATCH = "PIN_MISMATCH"
    }
}

private fun certLines(caller: CallerInfo): String =
    caller.certDigests.sorted().joinToString("\n") { AutofillTrust.formatDigest(it) }
