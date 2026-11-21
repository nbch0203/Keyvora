package com.keyvora.app.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CONTRACTS §4.1 / ADR-014 / SECURITY_REVIEW M-3: who may use webDomain. Browsers: allowlist of official signing
 * certificates (no TOFU). Apps: certificate pinned on first confirmed association.
 */
class AutofillTrustTest {
    private val own = "com.keyvora.app"
    private val chrome = "com.android.chrome"

    /** Chrome stable's official release certificate (Google's privileged-apps list). */
    private val chromeCert = "F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83"
    private val fakeCert = "B2".repeat(32)
    private val appCert = "A1".repeat(32)
    private val pins = InMemoryTrustPins()

    private fun pwd(id: Int) = FieldNode(id = id, isTextField = true, htmlTag = "input", htmlAttributes = mapOf("type" to "password"))
    private fun user(id: Int) = FieldNode(id = id, isTextField = true, htmlTag = "input", htmlAttributes = mapOf("type" to "email"))

    private fun page(domain: String?, scheme: String? = "https") =
        listOf(FieldNode<Int>(webDomain = domain, webScheme = scheme, children = listOf(user(1), pwd(2))))

    private fun decide(roots: List<FieldNode<Int>>, caller: CallerInfo) =
        AutofillTrust.decide(AutofillTrust.parseFor(roots, caller), caller, own, pins)

    @Test
    fun allowlistedBrowserWithOfficialCertificateIsTrustedWithoutConfirmationOrPin() {
        val caller = CallerInfo(chrome, setOf(chromeCert))
        assertEquals(TrustDecision.Trusted(FillTarget.Web("https://login.example.com", "login.example.com")), decide(page("login.example.com"), caller))
        assertEquals(TrustDecision.Trusted(FillTarget.Web("http://localhost:3000", "localhost:3000")), decide(page("localhost:3000", "http"), caller))
        // Nothing to confirm, nothing pinned: the allowlist is the identity.
        assertTrue(pins.all().isEmpty())
    }

    @Test
    fun anyOfficialKeyOrAVerifiedRotationIsAccepted() {
        // Chrome Beta has two official release keys in Google's list; either one is enough.
        val beta = "com.chrome.beta"
        val betaKey2 = "3D7A1223019AA39D9EA0E3436AB7C0896BFB4FB679F4DE5FE7C23F326C8F994A"
        assertEquals(TrustDecision.Trusted(FillTarget.Web("https://a.example", "a.example")), decide(page("a.example"), CallerInfo(beta, setOf(betaKey2))))
        // Key rotation: PackageManager reports the verified lineage, which still contains the official key.
        assertEquals(
            TrustDecision.Trusted(FillTarget.Web("https://a.example", "a.example")),
            decide(page("a.example"), CallerInfo(chrome, setOf("C0".repeat(32), chromeCert))),
        )
        // Same browser, lowercase digest: still the official certificate.
        assertEquals(
            TrustDecision.Trusted(FillTarget.Web("https://a.example", "a.example")),
            decide(page("a.example"), CallerInfo(chrome, setOf(chromeCert.lowercase()))),
        )
    }

    @Test
    fun allowlistedBrowserWithAnotherCertificateIsRefusedWithWarning() {
        // A sideloaded APK reusing Chrome's package name.
        val impostor = CallerInfo(chrome, setOf(fakeCert))
        assertEquals(TrustDecision.Refused(RefusalReason.BROWSER_CERT_MISMATCH), decide(page("bank.example"), impostor))
        assertTrue(RefusalReason.BROWSER_CERT_MISMATCH.warnUser)
        // Its webDomain is never honoured, and it never falls back to the app flow or to a confirmation.
        assertNull(AutofillTrust.parseFor(page("bank.example"), impostor).webDomain)
        assertEquals(TrustDecision.Refused(RefusalReason.BROWSER_CERT_MISMATCH), decide(page(null), impostor))
        assertEquals(TrustDecision.Refused(RefusalReason.BROWSER_CERT_MISMATCH), decide(page("bank.example", null), impostor))
        // A BROWSER pin left by an older (TOFU) version does not make it trusted, nor does an APP pin.
        pins.setPin(PinKind.BROWSER, chrome, setOf(fakeCert))
        pins.setPin(PinKind.APP, chrome, setOf(fakeCert))
        assertEquals(TrustDecision.Refused(RefusalReason.BROWSER_CERT_MISMATCH), decide(page("bank.example"), impostor))
        assertTrue(AutofillTrust.refusalMessage(RefusalReason.BROWSER_CERT_MISMATCH, chrome).contains(chrome))
    }

    private val nativeLogin = listOf(FieldNode(children = listOf(
        FieldNode(id = 1, isTextField = true, autofillHints = listOf("username")),
        FieldNode(id = 2, isTextField = true, autofillHints = listOf("password")),
    )))

    @Test
    fun unlistedBrowsersGetNothingOnWebPages() {
        // AUDIT AND-1: Bromite, Kiwi, Firefox Nightly, Fennec F-Droid… are browsers but not on the official list. An
        // androidapp://<browser> entry would match every site (phishing included), so their web pages get nothing,
        // even with an APP pin left from before this rule.
        for (pkg in listOf("org.bromite.bromite", "com.kiwibrowser.browser", "org.mozilla.fenix", "org.mozilla.fennec_fdroid")) {
            assertFalse(AutofillTrust.isKnownBrowser(pkg))
            val browser = CallerInfo(pkg, setOf(fakeCert), isBrowserApp = true)
            assertNull(AutofillTrust.parseFor(page("bank.example"), browser).webDomain)
            assertEquals(pkg, TrustDecision.Refused(RefusalReason.UNVERIFIED_BROWSER), decide(page("bank.example"), browser))
            pins.setPin(PinKind.BROWSER, pkg, setOf(fakeCert))
            pins.setPin(PinKind.APP, pkg, setOf(fakeCert))
            assertEquals(pkg, TrustDecision.Refused(RefusalReason.UNVERIFIED_BROWSER), decide(page("phishing.example"), browser))
            // Its own native screens (no web content) are still an app like any other.
            assertEquals(TrustDecision.Trusted(FillTarget.App(pkg)), decide(nativeLogin, browser))
        }
        assertTrue(RefusalReason.UNVERIFIED_BROWSER.warnUser)
        assertTrue(AutofillTrust.refusalMessage(RefusalReason.UNVERIFIED_BROWSER, "org.mozilla.fenix").contains("org.mozilla.fenix"))
    }

    @Test
    fun webPageInsideAnAppNeedsConfirmationAndNeverOffersPick() {
        // AUDIT AND-2: an app's in-app browser may show any site; its androidapp:// entries are only filled after a
        // confirmation, and «Elegir una entrada» is never offered on web content.
        val pkg = "com.example.social"
        val app = CallerInfo(pkg, setOf(appCert), isBrowserApp = false)
        pins.setPin(PinKind.APP, pkg, setOf(appCert))
        val web = AutofillTrust.parseFor(page("login-social.evil.example"), app)
        assertTrue(web.hasWebContent)
        assertEquals(TrustDecision.Trusted(FillTarget.App(pkg)), AutofillTrust.decide(web, app, own, pins))
        assertTrue(AutofillTrust.isWebContentInApp(web, FillTarget.App(pkg)))
        assertFalse(AutofillPick.shouldOffer(web, isApp = true, savedMatches = 0))
        // Native login screen of the same app: direct fill and «Elegir» as before.
        val native = AutofillTrust.parseFor(nativeLogin, app)
        assertFalse(AutofillTrust.isWebContentInApp(native, FillTarget.App(pkg)))
        assertTrue(AutofillPick.shouldOffer(native, isApp = true, savedMatches = 0))
        // Official browsers are web targets, never «web content in an app».
        val chromeForm = AutofillTrust.parseFor(page("bank.example"), CallerInfo(chrome, setOf(chromeCert), isBrowserApp = true))
        assertFalse(AutofillTrust.isWebContentInApp(chromeForm, FillTarget.Web("https://bank.example", "bank.example")))
    }

    @Test
    fun browserWithoutWebDomainOrWithBadSchemeIsRefused() {
        val caller = CallerInfo(chrome, setOf(chromeCert))
        assertEquals(TrustDecision.Refused(RefusalReason.BROWSER_WITHOUT_DOMAIN), decide(page(null), caller))
        assertEquals(TrustDecision.Refused(RefusalReason.UNSUPPORTED_SCHEME), decide(page("example.com", "javascript"), caller))
        // No scheme (API 26–27, or a bare host on 28+): http vs https unknown → never assume https (AND-SEC-1).
        assertEquals(TrustDecision.Refused(RefusalReason.UNKNOWN_SCHEME), decide(page("bank.example", null), caller))
        assertEquals(TrustDecision.Refused(RefusalReason.INVALID_DOMAIN), decide(page("evil.com/x?y"), caller))
    }

    @Test
    fun httpIsOnlyAllowedOnLoopbackHosts() {
        val caller = CallerInfo(chrome, setOf(chromeCert))
        // CONTRACTS §4 rule 2: http on a real host → nothing filled, generated or saved.
        for (host in listOf("bank.example", "127.0.0.1.evil.example", "localhost.evil.example", "128.0.0.1", "10.0.2.2:8080", "[::2]")) {
            assertEquals(host, TrustDecision.Refused(RefusalReason.INSECURE_PAGE), decide(page(host, "http"), caller))
        }
        for (host in listOf("localhost", "localhost:8765", "app.localhost", "127.0.0.1", "127.255.0.9:3000", "[::1]", "[::1]:8080")) {
            assertEquals(host, TrustDecision.Trusted(FillTarget.Web("http://$host", host)), decide(page(host, "http"), caller))
        }
        // https is unaffected.
        assertEquals(TrustDecision.Trusted(FillTarget.Web("https://bank.example", "bank.example")), decide(page("bank.example"), caller))
        assertFalse(RefusalReason.INSECURE_PAGE.warnUser)
        assertFalse(AutofillTrust.isLoopbackHost("127.0.0.256"))
        assertFalse(AutofillTrust.isLoopbackHost("[::1"))
    }

    @Test
    fun webDomainFromAnyOtherAppIsIgnored() {
        // AutoSpill-style: an app declares webDomain=bank.example in its own WebView/views.
        val caller = CallerInfo("com.evil.app", setOf(fakeCert))
        val form = AutofillTrust.parseFor(page("bank.example"), caller)
        assertNull(form.webDomain)
        val d = AutofillTrust.decide(form, caller, own, pins)
        assertEquals(TrustDecision.NeedsConfirmation(FillTarget.App("com.evil.app"), PinKind.APP, caller), d)
    }

    @Test
    fun nativeAppIsPinnedOnFirstAssociationAndRefusedOnMismatch() {
        val bank = "es.example.banco"
        val native = listOf(FieldNode(children = listOf(
            FieldNode(id = 1, isTextField = true, autofillHints = listOf("username")),
            FieldNode(id = 2, isTextField = true, autofillHints = listOf("password")),
        )))
        val genuine = CallerInfo(bank, setOf(appCert))
        assertEquals(TrustDecision.NeedsConfirmation(FillTarget.App(bank), PinKind.APP, genuine), decide(native, genuine))
        pins.setPin(PinKind.APP, bank, genuine.certDigests)
        assertEquals(TrustDecision.Trusted(FillTarget.App(bank)), decide(native, genuine))
        assertEquals(TrustDecision.Refused(RefusalReason.APP_CERT_MISMATCH), decide(native, CallerInfo(bank, setOf(fakeCert))))
        // Verified key rotation keeps the association.
        assertEquals(TrustDecision.Trusted(FillTarget.App(bank)), decide(native, CallerInfo(bank, setOf(appCert, "C0".repeat(32)))))
        // An app pin never makes a browser trusted and vice versa.
        assertNull(pins.pin(PinKind.BROWSER, bank))
        assertTrue(RefusalReason.APP_CERT_MISMATCH.warnUser)
    }

    @Test
    fun unverifiableOrOwnCallerIsRefused() {
        assertEquals(TrustDecision.Refused(RefusalReason.UNVERIFIABLE_CALLER), decide(page("example.com"), CallerInfo(chrome, emptySet())))
        assertEquals(TrustDecision.Refused(RefusalReason.UNVERIFIABLE_CALLER), decide(page(null), CallerInfo("com.some.app", emptySet())))
        assertEquals(TrustDecision.Refused(RefusalReason.OWN_APP), decide(page("example.com"), CallerInfo(own, setOf(chromeCert))))
        assertEquals(TrustDecision.Refused(RefusalReason.INVALID_PACKAGE), decide(page(null), CallerInfo("bad pkg", setOf(chromeCert))))
        val empty = listOf(FieldNode<Int>(webDomain = "example.com"))
        assertEquals(TrustDecision.Refused(RefusalReason.NO_FIELDS), decide(empty, CallerInfo(chrome, setOf(chromeCert))))
    }

    @Test
    fun certificateMatchingRules() {
        // App pins.
        assertTrue(AutofillTrust.certMatches(setOf("aa"), setOf("AA")))
        // Verified key rotation: the current lineage still contains the pinned (older) certificate.
        assertTrue(AutofillTrust.certMatches(setOf("OLD"), setOf("OLD", "NEW")))
        // Multiple signers must all still be present.
        assertFalse(AutofillTrust.certMatches(setOf("A", "B"), setOf("A")))
        assertFalse(AutofillTrust.certMatches(emptySet(), setOf("A")))
        assertFalse(AutofillTrust.certMatches(setOf("A"), emptySet()))
        // Official browser certificates: one official key among the verified signers/lineage is enough.
        assertTrue(AutofillTrust.officialCertMatches(setOf("A", "B"), setOf("b")))
        assertTrue(AutofillTrust.officialCertMatches(setOf("A"), setOf("OLD", "A")))
        assertFalse(AutofillTrust.officialCertMatches(setOf("A"), setOf("C")))
        assertFalse(AutofillTrust.officialCertMatches(setOf("A"), emptySet()))
        assertFalse(AutofillTrust.officialCertMatches(emptySet(), setOf("A")))
    }

    @Test
    fun onlyListedPackagesAreBrowsers() {
        assertTrue(AutofillTrust.isKnownBrowser("com.android.chrome"))
        assertTrue(AutofillTrust.isKnownBrowser("org.mozilla.firefox"))
        assertFalse(AutofillTrust.isKnownBrowser("com.android.chrome.evil"))
        assertFalse(AutofillTrust.isKnownBrowser("com.evil.browser"))
        assertTrue(AutofillTrust.isOfficialBrowser(CallerInfo(chrome, setOf(chromeCert))))
        assertFalse(AutofillTrust.isOfficialBrowser(CallerInfo(chrome, setOf(fakeCert))))
        assertFalse(AutofillTrust.isOfficialBrowser(CallerInfo("com.evil.browser", setOf(chromeCert))))
    }

    @Test
    fun allowlistIsWellFormedAndHasNoDiscontinuedBrowsers() {
        val hex = Regex("^[0-9A-F]{64}$")
        assertTrue(AutofillTrust.KNOWN_BROWSERS.isNotEmpty())
        for ((pkg, digests) in AutofillTrust.KNOWN_BROWSERS) {
            assertTrue(pkg, digests.isNotEmpty())
            digests.forEach { assertTrue("$pkg: $it", hex.matches(it)) }
        }
        for (gone in listOf("org.bromite.bromite", "com.kiwibrowser.browser", "org.mozilla.rocket", "org.mozilla.fennec_aurora", "com.android.browser")) {
            assertFalse(gone, AutofillTrust.isKnownBrowser(gone))
        }
    }

    @Test
    fun browserPinsFromTheTofuEraAreDroppedAndAppPinsKept() {
        pins.setPin(PinKind.BROWSER, chrome, setOf(chromeCert))
        pins.setPin(PinKind.BROWSER, "org.bromite.bromite", setOf(fakeCert))
        pins.setPin(PinKind.APP, "es.example.banco", setOf(appCert))
        AutofillTrust.forgetBrowserPins(pins)
        assertEquals(listOf(Triple(PinKind.APP, "es.example.banco", setOf(appCert))), pins.all())
        AutofillTrust.forgetBrowserPins(pins) // idempotent
        assertEquals(1, pins.all().size)
    }

    @Test
    fun pinsStoreAndForget() {
        pins.setPin(PinKind.APP, "a.b", setOf("X"))
        assertEquals(setOf("X"), pins.pin(PinKind.APP, "a.b"))
        assertEquals(1, pins.all().size)
        pins.forget(PinKind.APP, "a.b")
        assertNull(pins.pin(PinKind.APP, "a.b"))
        assertEquals("AB:CD:EF", AutofillTrust.formatDigest("abcdef"))
    }
}
