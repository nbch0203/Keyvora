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
) {
    val isEmpty: Boolean get() = usernameIds.isEmpty() && passwordIds.isEmpty()
    val allIds: List<ID> get() = usernameIds + passwordIds
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
    private val NEGATIVE_WORDS = Regex("search|buscar|otp|captcha|one.?time|verification|coupon|promo|zip|postal")
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
            val nameish = listOfNotNull(attrs["name"], attrs["id"]).joinToString(" ").lowercase()
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

        val text = listOfNotNull(node.idEntry, node.hint).joinToString(" ").lowercase()
        if (text.isNotEmpty()) {
            if (NEGATIVE_WORDS.containsMatchIn(text)) return FieldType.NONE
            if (PASSWORD_WORDS.containsMatchIn(text)) return FieldType.PASSWORD
            if (USERNAME_WORDS.containsMatchIn(text)) return FieldType.USERNAME
        }
        return FieldType.NONE
    }

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
        )
    }
}
