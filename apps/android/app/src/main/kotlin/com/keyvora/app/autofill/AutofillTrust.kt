package com.keyvora.app.autofill

import java.util.concurrent.ConcurrentHashMap

/**
 * Who asked for autofill: the package from the AssistStructure plus the SHA-256 digests (uppercase hex) of its
 * signing certificates as reported by PackageManager (current signers, including the verified rotation lineage).
 * Empty digests = the package could not be verified.
 */
data class CallerInfo(val packageName: String, val certDigests: Set<String>)

enum class PinKind { BROWSER, APP }

/** Device-local certificate pins (TOFU). Never synced, never backed up. */
interface TrustPins {
    fun pin(kind: PinKind, packageName: String): Set<String>?
}

interface MutableTrustPins : TrustPins {
    fun setPin(kind: PinKind, packageName: String, digests: Set<String>)
    fun forget(kind: PinKind, packageName: String)
    fun all(): List<Triple<PinKind, String, Set<String>>>
}

class InMemoryTrustPins : MutableTrustPins {
    private val map = ConcurrentHashMap<Pair<PinKind, String>, Set<String>>()
    override fun pin(kind: PinKind, packageName: String) = map[kind to packageName]
    override fun setPin(kind: PinKind, packageName: String, digests: Set<String>) { map[kind to packageName] = digests }
    override fun forget(kind: PinKind, packageName: String) { map.remove(kind to packageName) }
    override fun all() = map.map { (k, v) -> Triple(k.first, k.second, v) }
}

enum class RefusalReason(val warnUser: Boolean) {
    OWN_APP(false),
    NO_FIELDS(false),
    BROWSER_WITHOUT_DOMAIN(false),
    INVALID_DOMAIN(false),
    UNSUPPORTED_SCHEME(false),
    INVALID_PACKAGE(false),
    UNVERIFIABLE_CALLER(false),
    BROWSER_CERT_MISMATCH(true),
    APP_CERT_MISMATCH(true),
}

sealed interface TrustDecision {
    /** Caller verified against its pin: match [target] with the core. */
    data class Trusted(val target: FillTarget) : TrustDecision

    /** First use: the user must explicitly confirm (and thereby pin) [caller] before anything is filled/saved. */
    data class NeedsConfirmation(val target: FillTarget, val kind: PinKind, val caller: CallerInfo) : TrustDecision

    data class Refused(val reason: RefusalReason) : TrustDecision
}

/**
 * Autofill origin trust (CONTRACTS §4.1, ADR-014, SECURITY_REVIEW M-3). Pure logic, unit-tested.
 * - `webDomain` is honoured ONLY for a package in [KNOWN_BROWSERS] whose signing certificate matches the pin
 *   created after explicit confirmation (TOFU). Certificate change → refused with a warning.
 * - Any other app: `webDomain` is ignored; it can only match `androidapp://<package>` entries, and its certificate is
 *   pinned on first (confirmed) association; mismatch → refused with a warning.
 */
object AutofillTrust {
    /** Package names of mainstream browsers that support the Autofill Framework natively. */
    val KNOWN_BROWSERS: Set<String> = setOf(
        "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary",
        "org.chromium.chrome", "com.google.android.apps.chrome",
        "org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix", "org.mozilla.focus", "org.mozilla.klar",
        "com.microsoft.emmx", "com.microsoft.emmx.beta",
        "com.brave.browser", "com.brave.browser_beta",
        "com.opera.browser", "com.opera.browser.beta", "com.opera.gx",
        "com.vivaldi.browser",
        "com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta",
        "com.duckduckgo.mobile.android",
        "app.vanadium.browser", "org.bromite.bromite", "com.kiwibrowser.browser",
        "com.ecosia.android", "com.yandex.browser", "com.mi.globalbrowser",
    )

    private val DOMAIN = Regex("^[a-z0-9.\\-\\[\\]:]{1,253}$")
    private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$")

    fun isKnownBrowser(packageName: String): Boolean = packageName in KNOWN_BROWSERS

    /** Parses the structure honouring `webDomain` only for known browsers (other apps: webDomain ignored). */
    fun <ID> parseFor(roots: List<FieldNode<ID>>, caller: CallerInfo): ParsedForm<ID> =
        AutofillParser.parse(roots, useWebDomain = isKnownBrowser(caller.packageName))

    /** All pinned digests must be among the caller's current signers / verified lineage. */
    fun certMatches(pinned: Set<String>, current: Set<String>): Boolean =
        pinned.isNotEmpty() && current.isNotEmpty() && pinned.all { it.uppercase() in current.map(String::uppercase) }

    fun decide(form: ParsedForm<*>, caller: CallerInfo, ownPackage: String, pins: TrustPins): TrustDecision {
        val pkg = caller.packageName
        if (pkg == ownPackage) return TrustDecision.Refused(RefusalReason.OWN_APP)
        if (!PACKAGE.matches(pkg)) return TrustDecision.Refused(RefusalReason.INVALID_PACKAGE)
        if (form.isEmpty) return TrustDecision.Refused(RefusalReason.NO_FIELDS)

        val (target, kind) = if (isKnownBrowser(pkg)) {
            val domain = form.webDomain ?: return TrustDecision.Refused(RefusalReason.BROWSER_WITHOUT_DOMAIN)
            val scheme = form.webScheme ?: "https"
            if (scheme != "https" && scheme != "http") return TrustDecision.Refused(RefusalReason.UNSUPPORTED_SCHEME)
            if (!DOMAIN.matches(domain)) return TrustDecision.Refused(RefusalReason.INVALID_DOMAIN)
            FillTarget.Web("$scheme://$domain", domain) to PinKind.BROWSER
        } else {
            FillTarget.App(pkg) to PinKind.APP
        }

        if (caller.certDigests.isEmpty()) return TrustDecision.Refused(RefusalReason.UNVERIFIABLE_CALLER)
        val pinned = pins.pin(kind, pkg) ?: return TrustDecision.NeedsConfirmation(target, kind, caller)
        if (!certMatches(pinned, caller.certDigests)) {
            return TrustDecision.Refused(if (kind == PinKind.BROWSER) RefusalReason.BROWSER_CERT_MISMATCH else RefusalReason.APP_CERT_MISMATCH)
        }
        return TrustDecision.Trusted(target)
    }

    /** "AB:CD:…" grouping for display in confirmation dialogs. */
    fun formatDigest(hex: String): String = hex.uppercase().chunked(2).joinToString(":")

    fun refusalMessage(reason: RefusalReason, packageName: String): String = when (reason) {
        RefusalReason.BROWSER_CERT_MISMATCH ->
            "El certificado de firma del navegador $packageName no coincide con el que confirmaste. Keyvora no rellenará " +
                "hasta que lo revises en Ajustes → Apps y navegadores de confianza."
        RefusalReason.APP_CERT_MISMATCH ->
            "El certificado de firma de la app $packageName no coincide con el asociado a tus entradas. Puede ser una app " +
                "falsa con el mismo nombre. Keyvora no rellenará."
        else -> "Keyvora no rellena aquí."
    }
}
