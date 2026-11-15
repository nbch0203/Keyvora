package com.keyvora.app.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** CONTRACTS §4.1 / ADR-014 / SECURITY_REVIEW M-3: who may use webDomain, certificate pinning (TOFU). */
class AutofillTrustTest {
    private val own = "com.keyvora.app"
    private val chrome = "com.android.chrome"
    private val chromeCert = "A1".repeat(32)
    private val fakeCert = "B2".repeat(32)
    private val pins = InMemoryTrustPins()

    private fun pwd(id: Int) = FieldNode(id = id, isTextField = true, htmlTag = "input", htmlAttributes = mapOf("type" to "password"))
    private fun user(id: Int) = FieldNode(id = id, isTextField = true, htmlTag = "input", htmlAttributes = mapOf("type" to "email"))

    private fun page(domain: String?, scheme: String? = "https") =
        listOf(FieldNode<Int>(webDomain = domain, webScheme = scheme, children = listOf(user(1), pwd(2))))

    private fun decide(roots: List<FieldNode<Int>>, caller: CallerInfo) =
        AutofillTrust.decide(AutofillTrust.parseFor(roots, caller), caller, own, pins)

    @Test
    fun knownBrowserNeedsConfirmationTheFirstTime() {
        val caller = CallerInfo(chrome, setOf(chromeCert))
        val d = decide(page("accounts.example.com"), caller)
        assertEquals(TrustDecision.NeedsConfirmation(FillTarget.Web("https://accounts.example.com", "accounts.example.com"), PinKind.BROWSER, caller), d)
    }

    @Test
    fun pinnedBrowserIsTrustedAndHonoursWebDomain() {
        pins.setPin(PinKind.BROWSER, chrome, setOf(chromeCert))
        val d = decide(page("login.example.com"), CallerInfo(chrome, setOf(chromeCert)))
        assertEquals(TrustDecision.Trusted(FillTarget.Web("https://login.example.com", "login.example.com")), d)
        val local = decide(page("localhost:3000", "http"), CallerInfo(chrome, setOf(chromeCert)))
        assertEquals(TrustDecision.Trusted(FillTarget.Web("http://localhost:3000", "localhost:3000")), local)
    }

    @Test
    fun browserWithChangedCertificateIsRefusedWithWarning() {
        pins.setPin(PinKind.BROWSER, chrome, setOf(chromeCert))
        val d = decide(page("bank.example"), CallerInfo(chrome, setOf(fakeCert)))
        assertEquals(TrustDecision.Refused(RefusalReason.BROWSER_CERT_MISMATCH), d)
        assertTrue(RefusalReason.BROWSER_CERT_MISMATCH.warnUser)
    }

    @Test
    fun browserWithoutWebDomainOrWithBadSchemeIsRefused() {
        pins.setPin(PinKind.BROWSER, chrome, setOf(chromeCert))
        val caller = CallerInfo(chrome, setOf(chromeCert))
        assertEquals(TrustDecision.Refused(RefusalReason.BROWSER_WITHOUT_DOMAIN), decide(page(null), caller))
        assertEquals(TrustDecision.Refused(RefusalReason.UNSUPPORTED_SCHEME), decide(page("example.com", "javascript"), caller))
        // No scheme (API 26–27, or a bare host on 28+): http vs https unknown → never assume https (AND-SEC-1).
        assertEquals(TrustDecision.Refused(RefusalReason.UNKNOWN_SCHEME), decide(page("bank.example", null), caller))
        assertEquals(TrustDecision.Refused(RefusalReason.UNKNOWN_SCHEME), decide(page("bank.example", null), CallerInfo(chrome, setOf(fakeCert))))
        assertEquals(TrustDecision.Refused(RefusalReason.INVALID_DOMAIN), decide(page("evil.com/x?y"), caller))
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
        val genuine = CallerInfo(bank, setOf(chromeCert))
        assertTrue(decide(native, genuine) is TrustDecision.NeedsConfirmation)
        pins.setPin(PinKind.APP, bank, genuine.certDigests)
        assertEquals(TrustDecision.Trusted(FillTarget.App(bank)), decide(native, genuine))
        assertEquals(TrustDecision.Refused(RefusalReason.APP_CERT_MISMATCH), decide(native, CallerInfo(bank, setOf(fakeCert))))
        // An app pin never makes a browser trusted and vice versa.
        assertNull(pins.pin(PinKind.BROWSER, bank))
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
        assertTrue(AutofillTrust.certMatches(setOf("aa"), setOf("AA")))
        // Verified key rotation: the current lineage still contains the pinned (older) certificate.
        assertTrue(AutofillTrust.certMatches(setOf("OLD"), setOf("OLD", "NEW")))
        // Multiple signers must all still be present.
        assertFalse(AutofillTrust.certMatches(setOf("A", "B"), setOf("A")))
        assertFalse(AutofillTrust.certMatches(emptySet(), setOf("A")))
        assertFalse(AutofillTrust.certMatches(setOf("A"), emptySet()))
    }

    @Test
    fun onlyListedPackagesAreBrowsers() {
        assertTrue(AutofillTrust.isKnownBrowser("com.android.chrome"))
        assertTrue(AutofillTrust.isKnownBrowser("org.mozilla.firefox"))
        assertFalse(AutofillTrust.isKnownBrowser("com.android.chrome.evil"))
        assertFalse(AutofillTrust.isKnownBrowser("com.evil.browser"))
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
