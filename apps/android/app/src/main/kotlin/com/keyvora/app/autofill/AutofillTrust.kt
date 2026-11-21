package com.keyvora.app.autofill

import java.util.concurrent.ConcurrentHashMap

/**
 * Who asked for autofill: the package from the AssistStructure plus the SHA-256 digests (uppercase hex) of its
 * signing certificates as reported by PackageManager (current signers, including the verified rotation lineage).
 * Empty digests = the package could not be verified.
 * [isBrowserApp]: the package opens arbitrary https links (a web browser), as resolved by PackageManager.
 */
data class CallerInfo(val packageName: String, val certDigests: Set<String>, val isBrowserApp: Boolean = false)

/**
 * [BROWSER] is kept only so pins stored by older versions still load and can be listed/forgotten: browsers are now
 * verified against [AutofillTrust.KNOWN_BROWSERS] (official certificates) and [AutofillTrust.decide] never reads or
 * asks for a BROWSER pin.
 */
enum class PinKind { BROWSER, APP }

/** Device-local certificate pins (TOFU, apps only). Never synced, never backed up. */
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

    /** `webScheme` missing (always on API 26–27; on 28+ when the browser passes a bare host): http/https unknown. */
    UNKNOWN_SCHEME(false),

    /**
     * `http:` page on a non-loopback host (CONTRACTS §4 rule 2): nothing is filled, generated or saved there, since a
     * network attacker can read and rewrite the page.
     */
    INSECURE_PAGE(false),
    INVALID_PACKAGE(false),
    UNVERIFIABLE_CALLER(false),

    /** Package of an allowlisted browser signed with a certificate that is not the official one. */
    BROWSER_CERT_MISMATCH(true),

    /**
     * Web page in a browser that is not on [AutofillTrust.KNOWN_BROWSERS] (Firefox Nightly, Fennec, Mull, Tor…).
     * Its pages cannot be told apart by origin, so nothing is filled, picked, generated or saved there (AUDIT AND-1).
     */
    UNVERIFIED_BROWSER(true),
    APP_CERT_MISMATCH(true),
}

sealed interface TrustDecision {
    /** Caller verified (browser: official certificate; app: its pin): match [target] with the core. */
    data class Trusted(val target: FillTarget) : TrustDecision

    /**
     * First association of an app: the user must explicitly confirm (and thereby pin) [caller] before anything is
     * filled/saved. Browsers never get here; [kind] is always [PinKind.APP].
     */
    data class NeedsConfirmation(val target: FillTarget, val kind: PinKind, val caller: CallerInfo) : TrustDecision

    data class Refused(val reason: RefusalReason) : TrustDecision
}

/**
 * Autofill origin trust (CONTRACTS §4.1, ADR-014, SECURITY_REVIEW M-3). Pure logic, unit-tested.
 * - `webDomain` is honoured ONLY for a package in [KNOWN_BROWSERS] signed with one of its official certificates. No
 *   confirmation and no pin: the allowlist is the identity. Same package, other certificate (a sideloaded APK reusing
 *   the name) → refused with a warning. There is no first-use trust (TOFU) for browsers any more.
 * - Any other app, including discontinued browsers that are no longer listed (Bromite, Kiwi…): `webDomain` is ignored;
 *   it can only match `androidapp://<package>` entries, and its certificate is pinned on first (confirmed)
 *   association; mismatch → refused with a warning.
 */
object AutofillTrust {
    /**
     * Maintained release browsers (stable and beta channels) → official SHA-256 signing-certificate digests (uppercase
     * hex, no colons, same format as [CallerInfo.certDigests]); release-build signatures only (no `userdebug` keys).
     *
     * Source: Google's Credential Manager privileged-apps list,
     * https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json — downloaded 2026-11-20 (Last-Modified
     * 2026-09-16, SHA-256 of the file 0891ee2507894999ead3eb4f42e17936a2e8ed8f8fd95592535c9811ef319481).
     * Deliberately left out: discontinued browsers (Bromite, Kiwi: not in that list either; Firefox Lite
     * `org.mozilla.rocket`, Fennec `org.mozilla.fennec_aurora`, AOSP `com.android.browser`), dev/canary/nightly
     * channels, debug-only entries, and browsers missing from Google's list (Ecosia, Opera GX, Mi Browser) because
     * there is no official digest to check them against. Refresh from the same URL when a vendor rotates its key.
     */
    val KNOWN_BROWSERS: Map<String, Set<String>> = mapOf(
        "com.android.chrome" to setOf("F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83"),
        "com.chrome.beta" to setOf(
            "DA633D34B69E63AE2103B49D53CE052FC5F7F3C53AAB94FDC2A208BDFD14249C",
            "3D7A1223019AA39D9EA0E3436AB7C0896BFB4FB679F4DE5FE7C23F326C8F994A",
        ),
        "org.mozilla.firefox" to setOf("A78B62A5165B4494B2FEAD9E76A280D22D937FEE6251AECE599446B2EA319B04"),
        "org.mozilla.firefox_beta" to setOf("A78B62A5165B4494B2FEAD9E76A280D22D937FEE6251AECE599446B2EA319B04"),
        "org.mozilla.focus" to setOf("6203A473BE36D64EE37F87FA500EDBC79EAB930610AB9B9FA4CA7D5C1F1B4FFC"),
        "org.mozilla.klar" to setOf("6203A473BE36D64EE37F87FA500EDBC79EAB930610AB9B9FA4CA7D5C1F1B4FFC"),
        "com.microsoft.emmx" to setOf("01E1999710A82C2749B4D50C445DC85D670B6136089D0A766A73827C82A1EAC9"),
        "com.microsoft.emmx.beta" to setOf("01E1999710A82C2749B4D50C445DC85D670B6136089D0A766A73827C82A1EAC9"),
        "com.brave.browser" to setOf("9C2DB70513515FDBFBBC585B3EDF3D7123D4DC67C94FFD306361C1D79BBF18AC"),
        "com.brave.browser_beta" to setOf("9C2DB70513515FDBFBBC585B3EDF3D7123D4DC67C94FFD306361C1D79BBF18AC"),
        "com.opera.browser" to setOf("5D6AFBF87F652AF04647ADA0DF634CF22370900B164B09D50BD23AA2CB5285B8"),
        "com.opera.browser.beta" to setOf("5D6AFBF87F652AF04647ADA0DF634CF22370900B164B09D50BD23AA2CB5285B8"),
        "com.vivaldi.browser" to setOf("E8A78544655BA8C09817F732768F5689B1662EC4B2BC5A0BC0EC138D33CA3D1E"),
        "com.sec.android.app.sbrowser" to setOf("34DF0E7A9F1CF1892E45C056B4973CD81CCF148A4050D11AEA4AC5A65F900A42"),
        "com.sec.android.app.sbrowser.beta" to setOf("34DF0E7A9F1CF1892E45C056B4973CD81CCF148A4050D11AEA4AC5A65F900A42"),
        "com.duckduckgo.mobile.android" to setOf("BB7BB31C573C46A1DA7FC5C528A6ACF432108456FEEC50810C7F33694EB3D2D4"),
        "app.vanadium.browser" to setOf("C6ADB8B83C6D4C17D292AFDE56FD488A51D316FF8F2C11C5410223BFF8A7DBB3"),
        "com.yandex.browser" to setOf("ACA405DED8B25CB2E8C6DA69425D2B4307D087C1276FC06AD5942731CCC51DBA"),
    )

    private val DOMAIN = Regex("^[a-z0-9.\\-\\[\\]:]{1,253}$")
    private val IPV4_LOOPBACK = Regex("^127(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$")

    /**
     * Hosts where `http:` is allowed, as in the core's matching rules (CONTRACTS §4 rule 2): `localhost`,
     * `*.localhost`, `127.0.0.0/8` and `[::1]`, with or without a port. Anything else, including look-alikes such as
     * `127.0.0.1.evil.example` or `localhost.evil.example`, is not loopback.
     */
    fun isLoopbackHost(domain: String): Boolean {
        val host = if (domain.startsWith("[")) {
            domain.substringBefore(']', missingDelimiterValue = "") + "]"
        } else {
            domain.substringBefore(':')
        }
        return host == "localhost" || host.endsWith(".localhost") || host == "[::1]" || IPV4_LOOPBACK.matches(host)
    }
    private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$")

    /** Package name is on the allowlist (says nothing about the certificate; see [isOfficialBrowser]). */
    fun isKnownBrowser(packageName: String): Boolean = packageName in KNOWN_BROWSERS

    /** Allowlisted package signed with one of its official certificates. */
    fun isOfficialBrowser(caller: CallerInfo): Boolean =
        KNOWN_BROWSERS[caller.packageName]?.let { officialCertMatches(it, caller.certDigests) } ?: false

    /** Parses the structure honouring `webDomain` only for official browsers (anyone else: webDomain ignored). */
    fun <ID> parseFor(roots: List<FieldNode<ID>>, caller: CallerInfo): ParsedForm<ID> =
        AutofillParser.parse(roots, useWebDomain = isOfficialBrowser(caller))

    /** App pins: all pinned digests must be among the caller's current signers / verified lineage. */
    fun certMatches(pinned: Set<String>, current: Set<String>): Boolean =
        pinned.isNotEmpty() && current.isNotEmpty() && pinned.all { it.uppercase() in current.map(String::uppercase) }

    /**
     * Browsers: at least one official digest among the caller's verified signers / rotation lineage. Holding (or
     * having rotated from) an official key requires the vendor's private key, so one match identifies the vendor; a
     * listed browser may have several official keys (e.g. Chrome Beta).
     */
    fun officialCertMatches(official: Set<String>, current: Set<String>): Boolean {
        val have = current.mapTo(HashSet()) { it.uppercase() }
        return official.any { it.uppercase() in have }
    }

    fun decide(form: ParsedForm<*>, caller: CallerInfo, ownPackage: String, pins: TrustPins): TrustDecision {
        val pkg = caller.packageName
        if (pkg == ownPackage) return TrustDecision.Refused(RefusalReason.OWN_APP)
        if (!PACKAGE.matches(pkg)) return TrustDecision.Refused(RefusalReason.INVALID_PACKAGE)
        if (form.isEmpty) return TrustDecision.Refused(RefusalReason.NO_FIELDS)
        if (caller.certDigests.isEmpty()) return TrustDecision.Refused(RefusalReason.UNVERIFIABLE_CALLER)

        val official = KNOWN_BROWSERS[pkg]
        if (official != null) {
            // The certificate comes first: a listed name with a foreign certificate is an impostor, whatever the page.
            if (!officialCertMatches(official, caller.certDigests)) return TrustDecision.Refused(RefusalReason.BROWSER_CERT_MISMATCH)
            val domain = form.webDomain ?: return TrustDecision.Refused(RefusalReason.BROWSER_WITHOUT_DOMAIN)
            // Never assume https (QA-006 AND-SEC-1): the framework itself parses a bare host as http.
            val scheme = form.webScheme ?: return TrustDecision.Refused(RefusalReason.UNKNOWN_SCHEME)
            if (scheme != "https" && scheme != "http") return TrustDecision.Refused(RefusalReason.UNSUPPORTED_SCHEME)
            if (!DOMAIN.matches(domain)) return TrustDecision.Refused(RefusalReason.INVALID_DOMAIN)
            if (scheme == "http" && !isLoopbackHost(domain)) return TrustDecision.Refused(RefusalReason.INSECURE_PAGE)
            return TrustDecision.Trusted(FillTarget.Web("$scheme://$domain", domain))
        }

        // Web content in an unlisted browser: an `androidapp://<browser>` entry would match every site, phishing included.
        if (form.hasWebContent && caller.isBrowserApp) return TrustDecision.Refused(RefusalReason.UNVERIFIED_BROWSER)

        val target = FillTarget.App(pkg)
        val pinned = pins.pin(PinKind.APP, pkg) ?: return TrustDecision.NeedsConfirmation(target, PinKind.APP, caller)
        if (!certMatches(pinned, caller.certDigests)) return TrustDecision.Refused(RefusalReason.APP_CERT_MISMATCH)
        return TrustDecision.Trusted(target)
    }

    /**
     * A web page shown inside a native app (WebView, in-app browser, embedded OAuth). Its `webDomain` is not trusted, so
     * the page may be any site the app loaded: the app's `androidapp://` entries are only filled after a confirmation
     * that says so, and «Elegir una entrada» is never offered (CONTRACTS §4.1, AUDIT AND-2).
     */
    fun isWebContentInApp(form: ParsedForm<*>, target: FillTarget): Boolean = target is FillTarget.App && form.hasWebContent

    /**
     * Drops the BROWSER pins stored by versions that trusted browsers on first use. [decide] never reads them, so they
     * would only show up in Settings as if they still meant something.
     */
    fun forgetBrowserPins(pins: MutableTrustPins) {
        pins.all().filter { it.first == PinKind.BROWSER }.forEach { (kind, pkg, _) -> pins.forget(kind, pkg) }
    }

    /** "AB:CD:…" grouping for display in confirmation dialogs. */
    fun formatDigest(hex: String): String = hex.uppercase().chunked(2).joinToString(":")

    fun refusalMessage(reason: RefusalReason, packageName: String): String = when (reason) {
        RefusalReason.BROWSER_CERT_MISMATCH ->
            "$packageName usa el nombre de un navegador conocido, pero no está firmado con su certificado oficial. " +
                "Puede ser una copia falsa instalada fuera de la tienda. Keyvora no rellenará."
        RefusalReason.APP_CERT_MISMATCH ->
            "El certificado de firma de la app $packageName no coincide con el asociado a tus entradas. Puede ser una app " +
                "falsa con el mismo nombre. Keyvora no rellenará."
        RefusalReason.UNVERIFIED_BROWSER ->
            "$packageName es un navegador que no está en la lista de navegadores verificados de Keyvora, así que no puede " +
                "saber en qué sitio estás. Keyvora no rellena ni guarda contraseñas en sus páginas. Usa la versión estable " +
                "de Chrome, Firefox, Edge, Brave, Samsung Internet, DuckDuckGo, Vivaldi u Opera."
        else -> "Keyvora no rellena aquí."
    }
}
