package com.keyvora.app.autofill

/**
 * Pure (JVM-testable) model of an autofill view hierarchy and the field classification heuristics.
 * [ID] is `AutofillId` in the service and a plain value in unit tests.
 */
data class FieldNode<ID>(
    val id: ID? = null,
    val autofillHints: List<String> = emptyList(),
    val inputType: Int = 0,
    val htmlTag: String? = null,
    val htmlAttributes: Map<String, String> = emptyMap(),
    val idEntry: String? = null,
    val hint: String? = null,
    /** View content description (accessibility label); native apps sometimes name fields only this way. */
    val contentDescription: String? = null,
    val webDomain: String? = null,
    val webScheme: String? = null,
    /** autofillType == AUTOFILL_TYPE_TEXT */
    val isTextField: Boolean = false,
    val isVisible: Boolean = true,
    val importantForAutofill: Boolean = true,
    /** Current text (save flow only). */
    val textValue: String? = null,
    val children: List<FieldNode<ID>> = emptyList(),
) {
    override fun toString() = "FieldNode(id=$id, idEntry=$idEntry, children=${children.size})"
}

enum class FieldType { USERNAME, PASSWORD, NONE }

data class ParsedForm<ID>(
    /** Outermost web domain of the page (null for native screens). */
    val webDomain: String?,
    val webScheme: String?,
    /** Any HTML/web content in the structure (WebView or browser). */
    val hasWebContent: Boolean,
    val usernameIds: List<ID>,
    val passwordIds: List<ID>,
    val usernameValue: String? = null,
    val passwordValue: String? = null,
    /** Password fields explicitly marked as new (hint `newPassword`, `autocomplete=new-password`). */
    val newPasswordIds: List<ID> = emptyList(),
    /** Password fields explicitly marked as the current one (`autocomplete=current-password`, "old", "actual"…). */
    val currentPasswordIds: List<ID> = emptyList(),
    /** A password field is named like a sign-up / confirmation field ("confirm", "repite", "register"…). */
    val signupWords: Boolean = false,
    /** Numeric PIN fields (never receive a generated password). */
    val numericPasswordIds: List<ID> = emptyList(),
) {
    val isEmpty: Boolean get() = usernameIds.isEmpty() && passwordIds.isEmpty()
    val allIds: List<ID> get() = usernameIds + passwordIds

    /** Sign-up / change-password form: a field asks for a new password, or there are several password fields. */
    val isSignup: Boolean get() = newPasswordIds.isNotEmpty() || signupWords || passwordIds.size >= 2

    /**
     * Fields that receive a generated password: the explicitly "new" ones when marked; otherwise every password field
     * except an explicit "current" one (so password + confirmation both get it). Never numeric PINs.
     */
    val generatedPasswordIds: List<ID>
        get() = newPasswordIds.ifEmpty { passwordIds.filter { it !in currentPasswordIds } }.filter { it !in numericPasswordIds }
    override fun toString() = "ParsedForm(webDomain=$webDomain, users=${usernameIds.size}, passwords=${passwordIds.size})"
}

/** Where a fill request comes from. */
sealed interface FillTarget {
    /** Web page; [pageUrl] = scheme://webDomain, matched with core `findMatches`. */
    data class Web(val pageUrl: String, val domain: String) : FillTarget

    /** Native app; matched with core `findAppMatches` (`androidapp://<package>` entries only). */
    data class App(val packageName: String) : FillTarget

    data class None(val reason: String) : FillTarget
}

object AutofillParser {
    // android.text.InputType values (duplicated so the parser stays a pure JVM unit).
    const val TYPE_MASK_CLASS = 0x0000000f
    const val TYPE_MASK_VARIATION = 0x00000ff0
    const val TYPE_CLASS_TEXT = 0x00000001
    const val TYPE_CLASS_NUMBER = 0x00000002
    const val TYPE_TEXT_VARIATION_EMAIL_ADDRESS = 0x00000020
    const val TYPE_TEXT_VARIATION_PASSWORD = 0x00000080
    const val TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090
    const val TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS = 0x000000d0
    const val TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000e0
    const val TYPE_NUMBER_VARIATION_PASSWORD = 0x00000010

    private val PASSWORD_HINTS = setOf("password", "current-password", "new-password", "newpassword")
    private val USERNAME_HINTS = setOf("username", "email", "emailaddress", "newusername", "nickname")
    private val NON_LOGIN_HINTS = setOf(
        "smsotpcode", "one-time-code", "otp", "creditcardnumber", "creditcardsecuritycode", "postalcode", "postaladdress",
        "phonenumber", "name", "personname", "cc-number", "cc-csc", "search",
    )
    private val PASSWORD_WORDS = Regex("pass(word|wd|code)?|pwd|contrase[nñ]a|clave|senha|mot.?de.?passe|kennwort")
    private val USERNAME_WORDS = Regex("user|usuario|login|e-?mail|correo|account|cuenta|identifier|nick")
    private val NEGATIVE_WORDS = Regex("search|buscar|otp|captcha|one.?time|verification|verificaci|coupon|cup[oó]n|promo|zip|postal")

    /**
     * Chrome (third-party autofill mode) and WebView pass their own field-type predictions as HtmlInfo attributes;
     * they are the most reliable signal on pages without `autocomplete`.
     */
    private val PREDICTION_ATTRS = listOf("computed-autofill-hints", "crowdsourcing-autofill-hints", "ua-autofill-hints")
    private val PREDICTED_NEW_PASSWORD = setOf("NEW_PASSWORD", "ACCOUNT_CREATION_PASSWORD", "CONFIRMATION_PASSWORD", "PROBABLY_NEW_PASSWORD")
    private val PREDICTED_PASSWORD = PREDICTED_NEW_PASSWORD + setOf("PASSWORD", "NOT_NEW_PASSWORD")
    private val PREDICTED_USERNAME = setOf("USERNAME", "SINGLE_USERNAME", "USERNAME_AND_EMAIL_ADDRESS", "EMAIL_ADDRESS")
    private val NEW_PASSWORD_HINTS = setOf("newpassword", "new-password")
    private val NEW_PASSWORD_WORDS = Regex("new|nuev|confirm|repeat|repet|repit|retype|again|signup|sign.?up|regist|crear|create")
    private val CURRENT_PASSWORD_WORDS = Regex("current|old|actual|antigu|anterior")
    private val NON_TEXT_HTML_TYPES = setOf("hidden", "submit", "button", "checkbox", "radio", "image", "reset", "file", "search", "range", "color", "date")

    fun classify(node: FieldNode<*>): FieldType {
        if (!node.isTextField || !node.isVisible || !node.importantForAutofill) return FieldType.NONE

        val hints = node.autofillHints.map { it.lowercase().trim() }
        if (hints.any { it in PASSWORD_HINTS }) return FieldType.PASSWORD
        if (hints.any { it in USERNAME_HINTS }) return FieldType.USERNAME
        if (hints.any { it in NON_LOGIN_HINTS }) return FieldType.NONE

        if (node.htmlTag.equals("input", ignoreCase = true)) {
            val attrs = node.htmlAttributes.mapKeys { it.key.lowercase() }
            val type = attrs["type"]?.lowercase()
            val autocomplete = attrs["autocomplete"]?.lowercase().orEmpty()
            if (type in NON_TEXT_HTML_TYPES) return FieldType.NONE
            if (autocomplete.contains("one-time-code")) return FieldType.NONE
            if (type == "password" || autocomplete.contains("current-password") || autocomplete.contains("new-password")) {
                return FieldType.PASSWORD
            }
            if (type == "email" || autocomplete.split(' ').any { it == "username" || it == "email" }) return FieldType.USERNAME
            val predicted = predictions(node)
            if (predicted.any { it.startsWith("CREDIT_CARD") }) return FieldType.NONE
            if (predicted.any { it in PREDICTED_PASSWORD }) return FieldType.PASSWORD
            if (predicted.any { it in PREDICTED_USERNAME }) return FieldType.USERNAME
            // name / id, then the visible label or placeholder Chrome reports ("Correo o teléfono", "Contraseña"…).
            val nameish = listOfNotNull(attrs["name"], attrs["id"], attrs["label"], attrs["placeholder"], attrs["aria-label"])
                .joinToString(" ").lowercase()
            if (nameish.isNotEmpty()) {
                if (NEGATIVE_WORDS.containsMatchIn(nameish)) return FieldType.NONE
                if (PASSWORD_WORDS.containsMatchIn(nameish)) return FieldType.PASSWORD
                if (USERNAME_WORDS.containsMatchIn(nameish)) return FieldType.USERNAME
            }
        }

        val cls = node.inputType and TYPE_MASK_CLASS
        val variation = node.inputType and TYPE_MASK_VARIATION
        if (cls == TYPE_CLASS_TEXT) {
            when (variation) {
                TYPE_TEXT_VARIATION_PASSWORD, TYPE_TEXT_VARIATION_WEB_PASSWORD, TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ->
                    return FieldType.PASSWORD
                TYPE_TEXT_VARIATION_EMAIL_ADDRESS, TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS -> return FieldType.USERNAME
            }
        } else if (cls == TYPE_CLASS_NUMBER && variation == TYPE_NUMBER_VARIATION_PASSWORD) {
            return FieldType.PASSWORD
        }

        val text = listOfNotNull(node.idEntry, node.hint, node.contentDescription).joinToString(" ").lowercase()
        if (text.isNotEmpty()) {
            if (NEGATIVE_WORDS.containsMatchIn(text)) return FieldType.NONE
            if (PASSWORD_WORDS.containsMatchIn(text)) return FieldType.PASSWORD
            if (USERNAME_WORDS.containsMatchIn(text)) return FieldType.USERNAME
        }
        return FieldType.NONE
    }

    private fun autocomplete(node: FieldNode<*>): String =
        node.htmlAttributes.entries.firstOrNull { it.key.equals("autocomplete", true) }?.value?.lowercase().orEmpty()

    private fun names(node: FieldNode<*>): String {
        val attrs = node.htmlAttributes.mapKeys { it.key.lowercase() }
        return listOfNotNull(node.idEntry, node.hint, node.contentDescription, attrs["name"], attrs["id"], attrs["label"])
            .joinToString(" ").lowercase()
    }

    /** Password field explicitly marked as new (hint / autocomplete), for sign-up and change-password forms. */
    fun isNewPassword(node: FieldNode<*>): Boolean =
        node.autofillHints.any { it.lowercase().trim() in NEW_PASSWORD_HINTS } || autocomplete(node).contains("new-password") ||
            predictions(node).any { it in PREDICTED_NEW_PASSWORD }

    /** Chrome / WebView type predictions of a web field (upper-case tokens; empty for native views). */
    private fun predictions(node: FieldNode<*>): Set<String> = node.htmlAttributes.entries
        .filter { (k, _) -> PREDICTION_ATTRS.any { it.equals(k, ignoreCase = true) } }
        .flatMap { it.value.uppercase().split(',', ' ', ';') }
        .filter { it.isNotBlank() }
        .toSet()

    /** Password field explicitly marked as the current password (never receives a generated one). */
    fun isCurrentPassword(node: FieldNode<*>): Boolean =
        !isNewPassword(node) && (autocomplete(node).contains("current-password") || CURRENT_PASSWORD_WORDS.containsMatchIn(names(node)))

    private fun hasSignupWords(node: FieldNode<*>): Boolean = !isCurrentPassword(node) && NEW_PASSWORD_WORDS.containsMatchIn(names(node))

    private class Flat<ID>(val node: FieldNode<ID>, val domain: String?, val scheme: String?)

    /**
     * Classifies every field. Fields that belong to a different web domain than the outermost one (iframes) are
     * ignored: v1 never fills cross-origin frames (same policy as the extension, ADR-009).
     * With [useWebDomain] = false (any caller that is not a trusted browser, CONTRACTS §4.1) `webDomain` is ignored.
     */
    fun <ID> parse(roots: List<FieldNode<ID>>, useWebDomain: Boolean = true): ParsedForm<ID> {
        val flat = mutableListOf<Flat<ID>>()
        var hasWeb = false
        fun walk(n: FieldNode<ID>, domain: String?, scheme: String?) {
            val own = n.webDomain?.takeIf { useWebDomain && it.isNotBlank() }?.lowercase()
            val d = own ?: domain
            val s = if (own != null) n.webScheme?.lowercase() else scheme
            if (n.webDomain != null || n.htmlTag != null) hasWeb = true
            flat += Flat(n, d, s)
            n.children.forEach { walk(it, d, s) }
        }
        roots.forEach { walk(it, null, null) }

        val top = flat.firstOrNull { it.domain != null }
        val topDomain = top?.domain
        val inScope = flat.filter { it.node.id != null && it.domain == topDomain }

        val types = inScope.map { it to classify(it.node) }
        val users = types.filter { it.second == FieldType.USERNAME }.map { it.first }.toMutableList()
        val passwords = types.filter { it.second == FieldType.PASSWORD }.map { it.first }

        if (users.isEmpty() && passwords.isNotEmpty()) {
            // Fallback: the nearest plain text field before the first password field.
            val firstPwd = inScope.indexOf(passwords.first())
            inScope.subList(0, firstPwd).lastOrNull { f ->
                val n = f.node
                n.isTextField && n.isVisible && n.importantForAutofill && classify(n) == FieldType.NONE &&
                    !NEGATIVE_WORDS.containsMatchIn(listOfNotNull(n.idEntry, n.hint, n.htmlAttributes["name"]).joinToString(" ").lowercase()) &&
                    n.htmlAttributes["type"]?.lowercase() !in NON_TEXT_HTML_TYPES
            }?.let { users += it }
        }

        @Suppress("UNCHECKED_CAST")
        return ParsedForm(
            webDomain = topDomain,
            webScheme = top?.scheme,
            hasWebContent = hasWeb,
            usernameIds = users.map { it.node.id as ID },
            passwordIds = passwords.map { it.node.id as ID },
            usernameValue = users.firstNotNullOfOrNull { it.node.textValue?.takeIf(String::isNotEmpty) },
            passwordValue = passwords.firstNotNullOfOrNull { it.node.textValue?.takeIf(String::isNotEmpty) },
            newPasswordIds = passwords.filter { isNewPassword(it.node) }.map { it.node.id as ID },
            currentPasswordIds = passwords.filter { isCurrentPassword(it.node) }.map { it.node.id as ID },
            signupWords = passwords.any { hasSignupWords(it.node) },
            numericPasswordIds = passwords.filter { isNumeric(it.node) }.map { it.node.id as ID },
        )
    }

    private fun isNumeric(node: FieldNode<*>): Boolean =
        (node.inputType and TYPE_MASK_CLASS) == TYPE_CLASS_NUMBER ||
            node.htmlAttributes.entries.any { (k, v) -> k.equals("inputmode", true) && v.equals("numeric", true) }
}

/** When to add «Elegir una entrada de Keyvora» (link a saved account to a native app that has none yet). */
object AutofillPick {
    /**
     * Only on native app screens (never on web pages, including a page inside an app's WebView: a site must match by
     * origin), on a login form with a real password field (not a numeric PIN, not a sign-up form) and only when no
     * entry is linked to the app yet.
     */
    fun shouldOffer(form: ParsedForm<*>, isApp: Boolean, savedMatches: Int): Boolean =
        isApp && !form.hasWebContent && savedMatches == 0 && !form.isSignup && form.passwordIds.any { it !in form.numericPasswordIds }
}

/** When to add the «Generar contraseña segura» suggestion. */
object AutofillGenerate {
    /**
     * Only for fields that can take a generated password (not numeric PINs), and only on sign-up / change-password
     * forms — or, on a web page, when nothing is saved for it yet. Never on native-app logins without a sign-up hint
     * (system screens such as Wi-Fi or lock-screen PIN would otherwise get noise).
     */
    fun shouldOffer(form: ParsedForm<*>, isWeb: Boolean, savedMatches: Int): Boolean =
        form.generatedPasswordIds.isNotEmpty() && (form.isSignup || (isWeb && savedMatches == 0))
}
