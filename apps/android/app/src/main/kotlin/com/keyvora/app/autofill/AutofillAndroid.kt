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
import com.keyvora.app.core.Entry
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
        return CallerInfo(packageName, digests)
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
        for ((m, entry) in matches) {
            if (m.level == MatchLevel.EXACT && entry != null) {
                b.addDataset(dataset(context, form, entry))
            } else {
                b.addDataset(confirmDataset(context, form, target, m.entry.id, m.entry.title, m.pageHost))
            }
            count++
        }
        val save = saveInfo(form)
        save?.let { b.setSaveInfo(it) }
        if (count == 0 && save == null) return null
        b.setClientState(TargetExtras.toBundle(target))
        return b.build()
    }

    /** Certificate mismatch: a single non-filling entry that explains the refusal when tapped. */
    @Suppress("DEPRECATION")
    fun warning(context: Context, form: ParsedForm<AutofillId>, reason: RefusalReason, packageName: String): FillResponse {
        val b = Dataset.Builder(presentation(context, "Keyvora: no se rellenará", "Certificado de $packageName no coincide"))
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
        host: String,
    ): Dataset {
        val b = Dataset.Builder(presentation(context, title, "Requiere confirmación: $host"))
        form.allIds.forEach { b.setValue(it, null) }
        b.setAuthentication(authSender(context, AutofillAuthActivity.MODE_CONFIRM, target, entryId))
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
