package com.keyvora.app.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import com.keyvora.app.KeyvoraApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Android Autofill Framework service.
 * Trust (CONTRACTS §4.1): `webDomain` only from known browsers with a confirmed (pinned) signing certificate; any other
 * app only matches `androidapp://<package>` entries and its certificate is pinned on first confirmed association.
 * Matching itself is done by the core (`findMatches` / `findAppMatches`).
 */
class KeyvoraAutofillService : AutofillService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val container = (application as KeyvoraApp).container
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess(null)
        if (!container.core.isAvailable) return callback.onSuccess(null)
        container.autoLock.lockIfExpired() // before any dataset with credentials is built (AND-SEC-2)
        val pkg = structure.activityComponent?.packageName.orEmpty()

        val job = scope.launch {
            val response = try {
                val caller = container.callerResolver.resolve(pkg)
                val form = AssistStructureMapper.parse(structure, caller)
                when (val d = AutofillTrust.decide(form, caller, packageName, container.trustPins)) {
                    is TrustDecision.Refused ->
                        if (d.reason.warnUser) AutofillResponses.warning(this@KeyvoraAutofillService, form, d.reason, pkg) else null
                    is TrustDecision.NeedsConfirmation -> needsConfirmation(form, d)
                    is TrustDecision.Trusted ->
                        if (container.vault.isUnlocked) {
                            AutofillResponses.unlocked(this@KeyvoraAutofillService, container.vault, form, d.target)
                        } else {
                            AutofillResponses.locked(this@KeyvoraAutofillService, form, d.target)
                        }
                }
            } catch (_: Exception) {
                null // locked meanwhile or core error: offer nothing rather than something unverified
            }
            callback.onSuccess(response)
        }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }

    /** First contact with a browser / app: everything goes through the confirmation in [AutofillAuthActivity]. */
    private suspend fun needsConfirmation(form: ParsedForm<android.view.autofill.AutofillId>, d: TrustDecision.NeedsConfirmation) =
        if (d.kind == PinKind.APP && (application as KeyvoraApp).container.vault.isUnlocked) {
            // Do not nag for apps without saved credentials: only offer to save (which asks for confirmation).
            val vault = (application as KeyvoraApp).container.vault
            val hasEntries = vault.read { it.findAppMatches(d.caller.packageName).isNotEmpty() }
            if (hasEntries) {
                AutofillResponses.locked(this, form, d.target, "Keyvora: asociar esta app", "Confirma ${d.caller.packageName}")
            } else {
                // New app: «Elegir una entrada» on a login, «Generar contraseña» on a sign-up (both pin the app when
                // the user confirms), plus the save prompt.
                val b = android.service.autofill.FillResponse.Builder()
                val pick = AutofillPick.shouldOffer(form, isApp = true, savedMatches = 0)
                if (pick) b.addDataset(AutofillResponses.pickDataset(this, form, d.target))
                val generate = AutofillGenerate.shouldOffer(form, isWeb = false, savedMatches = 0)
                if (generate) b.addDataset(AutofillResponses.generateDataset(this, form, d.target))
                val save = AutofillResponses.saveInfo(form)
                save?.let { b.setSaveInfo(it) }
                if (pick || generate || save != null) b.build() else null
            }
        } else {
            val title = if (d.kind == PinKind.BROWSER) "Keyvora: confirmar navegador" else "Keyvora"
            AutofillResponses.locked(this, form, d.target, title, "Toca para continuar (${d.target.displayHost()})")
        }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val container = (application as KeyvoraApp).container
        container.autoLock.lockIfExpired()
        val contexts = request.fillContexts
        val last = contexts.lastOrNull()?.structure ?: return callback.onFailure("Sin datos")
        val pkg = last.activityComponent?.packageName.orEmpty()
        val caller = container.callerResolver.resolve(pkg)
        val form = AssistStructureMapper.parse(last, caller, withValues = true)
        val decision = AutofillTrust.decide(form, caller, packageName, container.trustPins)
        val password = form.passwordValue
        val (target, pinKind) = when (decision) {
            is TrustDecision.Trusted -> decision.target to null
            is TrustDecision.NeedsConfirmation -> decision.target to decision.kind
            is TrustDecision.Refused -> return callback.onFailure(AutofillTrust.refusalMessage(decision.reason, pkg))
        }
        if (password.isNullOrEmpty()) return callback.onFailure("Nada que guardar")
        // Multi-page logins: the username may be in an earlier context.
        val username = form.usernameValue ?: contexts.dropLast(1).reversed()
            .firstNotNullOfOrNull { AssistStructureMapper.parse(it.structure, caller, withValues = true).usernameValue }
            .orEmpty()

        val token = container.pendingSaves.put(PendingSave(target, username, password, System.currentTimeMillis(), caller, pinKind))
        val intent = Intent(this, AutofillSaveActivity::class.java).putExtra(AutofillSaveActivity.EXTRA_TOKEN, token)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val flags = PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE
            callback.onSuccess(PendingIntent.getActivity(this, token.hashCode(), intent, flags).intentSender)
        } else {
            startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            callback.onSuccess()
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
