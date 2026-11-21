package com.keyvora.app.autofill

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.SaveInfo
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.core.content.edit
import com.keyvora.app.R
import com.keyvora.app.core.CoreBridge
import com.keyvora.app.core.Entry
import com.keyvora.app.core.EntryInput
import com.keyvora.app.core.MatchLevel
import com.keyvora.app.vault.VaultManager
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** Maps the framework [AssistStructure] to the pure [FieldNode] model of [AutofillParser]. */
object AssistStructureMapper {
    /** webDomain is only honoured for known browsers (AutofillTrust.parseFor, CONTRACTS §4.1). */
    fun parse(structure: AssistStructure, caller: CallerInfo, withValues: Boolean = false): ParsedForm<AutofillId> =
        AutofillTrust.parseFor((0 until structure.windowNodeCount).map { map(structure.getWindowNodeAt(it).rootViewNode, withValues) }, caller)

    private fun map(v: AssistStructure.ViewNode, withValues: Boolean): FieldNode<AutofillId> {
        val important = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            v.importantForAutofill != View.IMPORTANT_FOR_AUTOFILL_NO &&
                v.importantForAutofill != View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        } else {
            true
        }
        return FieldNode(
            id = v.autofillId,
            autofillHints = v.autofillHints?.toList().orEmpty(),
            inputType = v.inputType,
            htmlTag = v.htmlInfo?.tag,
            htmlAttributes = v.htmlInfo?.attributes?.mapNotNull { p -> p.first?.let { k -> k to (p.second ?: "") } }?.toMap().orEmpty(),
            idEntry = v.idEntry,
            hint = v.hint,
            contentDescription = v.contentDescription?.toString(),
            webDomain = v.webDomain,
            webScheme = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) v.webScheme else null,
            isTextField = v.autofillType == View.AUTOFILL_TYPE_TEXT,
            isVisible = v.visibility == View.VISIBLE,
            importantForAutofill = important,
            textValue = if (withValues) v.autofillValue?.takeIf { it.isText }?.textValue?.toString() else null,
            children = (0 until v.childCount).map { map(v.getChildAt(it), withValues) },
        )
    }
}

/** Resolves the signing-certificate digests of the requesting package (needs package visibility: <queries>). */
class CallerResolver(private val context: Context) {
    fun resolve(packageName: String): CallerInfo {
        val digests = try {
            signatures(packageName).map { sha256Hex(it.toByteArray()) }.toSet()
        } catch (_: PackageManager.NameNotFoundException) {
            emptySet()
        } catch (_: SecurityException) {
            emptySet()
        }
        return CallerInfo(packageName, digests, isBrowserApp(packageName))
    }

    /**
     * A web browser: it handles a generic https link (an app with verified App Links only handles its own hosts).
     * Needs the matching `<queries>` intent in the manifest on API 30+.
     */
    private fun isBrowserApp(pkg: String): Boolean = try {
        val probe = Intent(Intent.ACTION_VIEW, Uri.parse("https://keyvora-browser-probe.invalid/"))
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .setPackage(pkg)
        @Suppress("DEPRECATION")
        context.packageManager.queryIntentActivities(probe, PackageManager.MATCH_ALL).isNotEmpty()
    } catch (_: RuntimeException) {
        false
    }

    @SuppressLint("PackageManagerGetSignatures") // API < 28 only; API 28+ uses the verified SigningInfo lineage.
    private fun signatures(pkg: String): List<Signature> {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo ?: return emptyList()
            (if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory)?.toList().orEmpty()
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures?.toList().orEmpty()
        }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02X".format(it) }
}

/** Device-local certificate pins in their own SharedPreferences file (excluded from backups like everything else). */
class PrefsTrustPins(private val prefs: SharedPreferences) : MutableTrustPins {
    private fun key(kind: PinKind, pkg: String) = "${kind.name}|$pkg"

    override fun pin(kind: PinKind, packageName: String): Set<String>? =
        prefs.getString(key(kind, packageName), null)?.split(',')?.filter { it.isNotEmpty() }?.toSet()?.takeIf { it.isNotEmpty() }

    override fun setPin(kind: PinKind, packageName: String, digests: Set<String>) {
        prefs.edit(commit = true) { putString(key(kind, packageName), digests.sorted().joinToString(",")) }
    }

    override fun forget(kind: PinKind, packageName: String) {
        prefs.edit(commit = true) { remove(key(kind, packageName)) }
    }

    override fun all(): List<Triple<PinKind, String, Set<String>>> = prefs.all.mapNotNull { (k, v) ->
        val kind = PinKind.entries.firstOrNull { k.startsWith(it.name + "|") } ?: return@mapNotNull null
        Triple(kind, k.substringAfter('|'), (v as? String)?.split(',')?.toSet().orEmpty())
    }.sortedBy { it.second }
}

/** Target <-> Intent extras (non-secret). */
object TargetExtras {
    private const val KIND = "keyvora.target.kind"
    private const val VALUE = "keyvora.target.value"
    private const val DOMAIN = "keyvora.target.domain"

    fun put(intent: Intent, t: FillTarget) {
        when (t) {
            is FillTarget.Web -> intent.putExtra(KIND, "web").putExtra(VALUE, t.pageUrl).putExtra(DOMAIN, t.domain)
            is FillTarget.App -> intent.putExtra(KIND, "app").putExtra(VALUE, t.packageName)
            is FillTarget.None -> Unit
        }
    }

    fun get(intent: Intent): FillTarget {
        val v = intent.getStringExtra(VALUE) ?: return FillTarget.None("missing")
        return when (intent.getStringExtra(KIND)) {
            "web" -> FillTarget.Web(v, intent.getStringExtra(DOMAIN) ?: return FillTarget.None("missing"))
            "app" -> FillTarget.App(v)
            else -> FillTarget.None("missing")
        }
    }

    fun get(bundle: Bundle?): FillTarget = bundle?.let { get(Intent().putExtras(it)) } ?: FillTarget.None("missing")

    fun toBundle(t: FillTarget): Bundle = Intent().also { put(it, t) }.extras ?: Bundle()
}

fun FillTarget.displayHost(): String = when (this) {
    is FillTarget.Web -> domain
    is FillTarget.App -> packageName
    is FillTarget.None -> ""
}

/** Builds FillResponses / Datasets. Exact matches are offered directly; sameSite only behind a confirmation. */
object AutofillResponses {
    private const val MAX_DATASETS = 12

    fun presentation(context: Context, title: String, subtitle: String?): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_title, title)
            setTextViewText(R.id.autofill_subtitle, subtitle ?: "")
        }

    fun authSender(context: Context, mode: String, target: FillTarget, entryId: String? = null, reason: String? = null): IntentSender {
        val intent = Intent(context, AutofillAuthActivity::class.java)
            .putExtra(AutofillAuthActivity.EXTRA_MODE, mode)
            .putExtra(AutofillAuthActivity.EXTRA_ENTRY_ID, entryId)
            .putExtra(AutofillAuthActivity.EXTRA_REASON, reason)
        TargetExtras.put(intent, target)
        // The autofill framework adds EXTRA_ASSIST_STRUCTURE to this explicit intent: it must be mutable (API 31+).
        val flags = PendingIntent.FLAG_CANCEL_CURRENT or
            (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
        return PendingIntent.getActivity(context, UUID.randomUUID().hashCode(), intent, flags).intentSender
    }

    /** Locked vault: one authentication entry that opens [AutofillAuthActivity]. */
    @Suppress("DEPRECATION") // setAuthentication(ids, sender, RemoteViews): the Presentations overload needs API 33.
    fun locked(
        context: Context,
        form: ParsedForm<AutofillId>,
        target: FillTarget,
        title: String = "Keyvora bloqueado",
        subtitle: String = "Toca para desbloquear (${target.displayHost()})",
    ): FillResponse {
        val b = FillResponse.Builder()
            .setAuthentication(
                form.allIds.toTypedArray(),
                authSender(context, AutofillAuthActivity.MODE_UNLOCK, target),
                presentation(context, title, subtitle),
            )
        saveInfo(form)?.let { b.setSaveInfo(it) }
        b.setClientState(TargetExtras.toBundle(target))
        return b.build()
    }

    /** Unlocked vault: datasets from the core's matches (CONTRACTS §4). Null when there is nothing to offer. */
    suspend fun unlocked(context: Context, vault: VaultManager, form: ParsedForm<AutofillId>, target: FillTarget): FillResponse? {
        val matches = vault.read { s ->
            val found = when (target) {
                is FillTarget.Web -> s.findMatches(target.pageUrl)
                is FillTarget.App -> s.findAppMatches(target.packageName)
                is FillTarget.None -> emptyList()
            }
            found.filter { it.level != MatchLevel.NONE }
                .sortedBy { if (it.level == MatchLevel.EXACT) 0 else 1 }
                .take(MAX_DATASETS)
                .map { m -> m to (if (m.level == MatchLevel.EXACT) s.getEntry(m.entry.id) else null) }
        }
        val b = FillResponse.Builder()
        var count = 0
        // A web page inside an app may be any site it loaded (in-app browser, phishing link): confirm every fill.
        val webInApp = AutofillTrust.isWebContentInApp(form, target)
        for ((m, entry) in matches) {
            if (m.level == MatchLevel.EXACT && entry != null && !webInApp) {
                b.addDataset(dataset(context, form, entry))
            } else {
                val subtitle = if (webInApp) "Página web dentro de la app: confirmar" else "Requiere confirmación: ${m.pageHost}"
                b.addDataset(confirmDataset(context, form, target, m.entry.id, m.entry.title, subtitle))
            }
            count++
        }
        if (AutofillPick.shouldOffer(form, target is FillTarget.App, count)) {
            b.addDataset(pickDataset(context, form, target))
            count++
        }
        if (AutofillGenerate.shouldOffer(form, target is FillTarget.Web, count)) {
            b.addDataset(generateDataset(context, form, target))
            count++
        }
        val save = saveInfo(form)
        save?.let { b.setSaveInfo(it) }
        if (count == 0 && save == null) return null
        b.setClientState(TargetExtras.toBundle(target))
        return b.build()
    }

    /** Certificate mismatch or unverified browser: a single non-filling entry that explains the refusal when tapped. */
    @Suppress("DEPRECATION")
    fun warning(context: Context, form: ParsedForm<AutofillId>, reason: RefusalReason, packageName: String): FillResponse {
        val subtitle = if (reason == RefusalReason.UNVERIFIED_BROWSER) {
            "Navegador no verificado: $packageName"
        } else {
            "Certificado de $packageName no coincide"
        }
        val b = Dataset.Builder(presentation(context, "Keyvora: no se rellenará", subtitle))
        form.allIds.forEach { b.setValue(it, null) }
        b.setAuthentication(authSender(context, AutofillAuthActivity.MODE_WARN, FillTarget.App(packageName), reason = reason.name))
        return FillResponse.Builder().addDataset(b.build()).build()
    }

    @Suppress("DEPRECATION") // Dataset.Builder(RemoteViews)/setValue: the Field API needs API 33.
    fun dataset(context: Context, form: ParsedForm<AutofillId>, entry: Entry): Dataset {
        val b = Dataset.Builder(presentation(context, entry.title, entry.username.ifEmpty { null }))
        form.usernameIds.forEach { b.setValue(it, AutofillValue.forText(entry.username)) }
        form.passwordIds.forEach { b.setValue(it, AutofillValue.forText(entry.password)) }
        return b.build()
    }

    @Suppress("DEPRECATION")
    private fun confirmDataset(
        context: Context,
        form: ParsedForm<AutofillId>,
        target: FillTarget,
        entryId: String,
        title: String,
        subtitle: String,
    ): Dataset {
        val b = Dataset.Builder(presentation(context, title, subtitle))
        form.allIds.forEach { b.setValue(it, null) }
        b.setAuthentication(authSender(context, AutofillAuthActivity.MODE_CONFIRM, target, entryId))
        return b.build()
    }

    /** «Generar contraseña segura»: opens [AutofillAuthActivity] in MODE_GENERATE (generate, save, then fill). */
    @Suppress("DEPRECATION")
    fun generateDataset(context: Context, form: ParsedForm<AutofillId>, target: FillTarget): Dataset {
        val b = Dataset.Builder(presentation(context, "Generar contraseña segura", "Keyvora la guardará para ${target.displayHost()}"))
        (form.usernameIds + form.generatedPasswordIds).forEach { b.setValue(it, null) }
        b.setAuthentication(authSender(context, AutofillAuthActivity.MODE_GENERATE, target))
        return b.build()
    }

    /** «Elegir una entrada de Keyvora»: opens [AutofillAuthActivity] in MODE_PICK (choose, link to the app, fill). */
    @Suppress("DEPRECATION")
    fun pickDataset(context: Context, form: ParsedForm<AutofillId>, target: FillTarget): Dataset {
        val b = Dataset.Builder(presentation(context, "Elegir una entrada de Keyvora", "Vincula una cuenta guardada a esta app"))
        form.allIds.forEach { b.setValue(it, null) }
        b.setAuthentication(authSender(context, AutofillAuthActivity.MODE_PICK, target))
        return b.build()
    }

    /** Result of MODE_GENERATE: the new password in the new-password fields (+ the username if the user gave one). */
    @Suppress("DEPRECATION")
    fun generatedDataset(context: Context, form: ParsedForm<AutofillId>, username: String, password: String): Dataset {
        val b = Dataset.Builder(presentation(context, "Contraseña generada", username.ifEmpty { null }))
        if (username.isNotEmpty()) form.usernameIds.forEach { b.setValue(it, AutofillValue.forText(username)) }
        form.generatedPasswordIds.forEach { b.setValue(it, AutofillValue.forText(password)) }
        return b.build()
    }

    fun saveInfo(form: ParsedForm<AutofillId>): SaveInfo? {
        if (form.passwordIds.isEmpty()) return null
        var type = SaveInfo.SAVE_DATA_TYPE_PASSWORD
        if (form.usernameIds.isNotEmpty()) type = type or SaveInfo.SAVE_DATA_TYPE_USERNAME
        return SaveInfo.Builder(type, form.passwordIds.toTypedArray()).apply {
            if (form.usernameIds.isNotEmpty()) setOptionalIds(form.usernameIds.toTypedArray())
        }.build()
    }
}

/** Shared by the save and generate flows: entry URL, first-association pinning and the vault write. */
object AutofillStore {
    const val ERR_PIN_MISMATCH = "PIN_MISMATCH"

    /** URL stored in the entry: page origin computed by the core, or `androidapp://<package>`. */
    fun entryUrl(core: CoreBridge, target: FillTarget): String? = when (target) {
        is FillTarget.Web -> runCatching { core.pageOrigin(target.pageUrl) }.getOrNull() ?: target.pageUrl
        is FillTarget.App -> "androidapp://${target.packageName}"
        is FillTarget.None -> null
    }

    /** Pins the caller on first association; refuses if a different certificate was pinned meanwhile. */
    fun confirmPin(pins: MutableTrustPins, kind: PinKind, caller: CallerInfo) {
        val existing = pins.pin(kind, caller.packageName)
        if (existing != null && !AutofillTrust.certMatches(existing, caller.certDigests)) throw IllegalStateException(ERR_PIN_MISMATCH)
        if (existing == null) pins.setPin(kind, caller.packageName, caller.certDigests)
    }

    /** Adds [url] (`androidapp://<package>`) to an existing entry, leaving everything else as it is. */
    suspend fun link(vault: VaultManager, entryId: String, url: String) {
        val now = vault.now()
        vault.mutate { s ->
            val e = s.getEntry(entryId)
            if (url !in e.urls) s.updateEntry(entryId, EntryInput(e.title, e.username, e.password, e.urls + url, e.notes), now)
        }
    }

    /** Creates a new entry, or updates [existingId] (adding the URL if missing). */
    suspend fun save(vault: VaultManager, url: String, existingId: String?, title: String, username: String, password: String) {
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
}

/** Credentials captured by onSaveRequest, held in memory only until the save activity consumes them. */
class PendingSave(
    val target: FillTarget,
    val username: String,
    val password: String,
    val createdAt: Long,
    val caller: CallerInfo,
    /** Non-null when the caller is not pinned yet: saving requires confirming (and pinning) it. */
    val pinKind: PinKind? = null,
) {
    override fun toString() = "PendingSave(target=$target)"
}

class PendingSaveStore(private val ttlMs: Long = 10 * 60_000L) {
    private val items = ConcurrentHashMap<String, PendingSave>()

    fun put(save: PendingSave): String {
        purge(save.createdAt)
        val token = UUID.randomUUID().toString()
        items[token] = save
        return token
    }

    fun peek(token: String?, now: Long): PendingSave? {
        purge(now)
        return token?.let { items[it] }
    }

    fun remove(token: String?) {
        token?.let { items.remove(it) }
    }

    fun clear() = items.clear()

    private fun purge(now: Long) {
        items.entries.removeIf { now - it.value.createdAt > ttlMs }
    }
}
