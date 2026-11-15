package com.keyvora.app.autofill

import com.keyvora.app.autofill.AutofillParser.TYPE_CLASS_NUMBER
import com.keyvora.app.autofill.AutofillParser.TYPE_CLASS_TEXT
import com.keyvora.app.autofill.AutofillParser.TYPE_NUMBER_VARIATION_PASSWORD
import com.keyvora.app.autofill.AutofillParser.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
import com.keyvora.app.autofill.AutofillParser.TYPE_TEXT_VARIATION_PASSWORD
import com.keyvora.app.autofill.AutofillParser.TYPE_TEXT_VARIATION_WEB_PASSWORD
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillParserTest {
    private fun text(id: Int, block: FieldNode<Int>.() -> FieldNode<Int> = { this }) =
        FieldNode(id = id, isTextField = true, inputType = TYPE_CLASS_TEXT).block()

    private fun root(vararg children: FieldNode<Int>, webDomain: String? = null, webScheme: String? = null) =
        FieldNode<Int>(webDomain = webDomain, webScheme = webScheme, children = children.toList())

    @Test
    fun autofillHintsWin() {
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(text(1) { copy(autofillHints = listOf("password")) }))
        assertEquals(FieldType.USERNAME, AutofillParser.classify(text(1) { copy(autofillHints = listOf("emailAddress")) }))
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(text(1) { copy(autofillHints = listOf("new-password")) }))
        assertEquals(FieldType.NONE, AutofillParser.classify(text(1) { copy(autofillHints = listOf("smsOTPCode"), idEntry = "password") }))
    }

    @Test
    fun htmlAttributes() {
        fun input(vararg attrs: Pair<String, String>) = text(1) { copy(htmlTag = "input", htmlAttributes = attrs.toMap()) }
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(input("type" to "password")))
        assertEquals(FieldType.USERNAME, AutofillParser.classify(input("type" to "email")))
        assertEquals(FieldType.USERNAME, AutofillParser.classify(input("type" to "text", "autocomplete" to "username")))
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(input("type" to "text", "autocomplete" to "current-password")))
        assertEquals(FieldType.USERNAME, AutofillParser.classify(input("type" to "text", "name" to "login_user")))
        assertEquals(FieldType.NONE, AutofillParser.classify(input("type" to "hidden", "name" to "password")))
        assertEquals(FieldType.NONE, AutofillParser.classify(input("type" to "text", "autocomplete" to "one-time-code")))
        assertEquals(FieldType.NONE, AutofillParser.classify(input("type" to "search", "name" to "user")))
    }

    @Test
    fun inputTypes() {
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(text(1) { copy(inputType = TYPE_CLASS_TEXT or TYPE_TEXT_VARIATION_PASSWORD) }))
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(text(1) { copy(inputType = TYPE_CLASS_TEXT or TYPE_TEXT_VARIATION_WEB_PASSWORD) }))
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(text(1) { copy(inputType = TYPE_CLASS_NUMBER or TYPE_NUMBER_VARIATION_PASSWORD) }))
        assertEquals(FieldType.USERNAME, AutofillParser.classify(text(1) { copy(inputType = TYPE_CLASS_TEXT or TYPE_TEXT_VARIATION_EMAIL_ADDRESS) }))
        assertEquals(FieldType.NONE, AutofillParser.classify(text(1)))
    }

    @Test
    fun idAndHintHeuristicsInSpanishAndEnglish() {
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(text(1) { copy(idEntry = "et_contrasena") }))
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(text(1) { copy(hint = "Contraseña") }))
        assertEquals(FieldType.USERNAME, AutofillParser.classify(text(1) { copy(hint = "Correo electrónico") }))
        assertEquals(FieldType.USERNAME, AutofillParser.classify(text(1) { copy(idEntry = "username_input") }))
        assertEquals(FieldType.NONE, AutofillParser.classify(text(1) { copy(idEntry = "search_user") }))
    }

    @Test
    fun nonTextInvisibleOrExcludedFieldsAreIgnored() {
        val pwd = TYPE_CLASS_TEXT or TYPE_TEXT_VARIATION_PASSWORD
        assertEquals(FieldType.NONE, AutofillParser.classify(text(1) { copy(inputType = pwd, isTextField = false) }))
        assertEquals(FieldType.NONE, AutofillParser.classify(text(1) { copy(inputType = pwd, isVisible = false) }))
        assertEquals(FieldType.NONE, AutofillParser.classify(text(1) { copy(inputType = pwd, importantForAutofill = false) }))
    }

    @Test
    fun usernameFallsBackToPrecedingTextField() {
        val form = AutofillParser.parse(
            listOf(root(text(1) { copy(idEntry = "field_a") }, text(2) { copy(inputType = TYPE_CLASS_TEXT or TYPE_TEXT_VARIATION_PASSWORD) })),
        )
        assertEquals(listOf(1), form.usernameIds)
        assertEquals(listOf(2), form.passwordIds)
        assertEquals(null, form.webDomain)
    }

    @Test
    fun iframeFieldsOfAnotherDomainAreIgnored() {
        val iframe = FieldNode(
            webDomain = "evil.example",
            htmlTag = "iframe",
            children = listOf(text(3) { copy(htmlTag = "input", htmlAttributes = mapOf("type" to "password")) }),
        )
        val page = root(
            text(1) { copy(htmlTag = "input", htmlAttributes = mapOf("type" to "email")) },
            text(2) { copy(htmlTag = "input", htmlAttributes = mapOf("type" to "password")) },
            iframe,
            webDomain = "login.example.com",
            webScheme = "https",
        )
        val form = AutofillParser.parse(listOf(page))
        assertEquals("login.example.com", form.webDomain)
        assertEquals(listOf(1), form.usernameIds)
        assertEquals(listOf(2), form.passwordIds)
        assertTrue(form.hasWebContent)
    }

    @Test
    fun valuesAreCollectedForSave() {
        val form = AutofillParser.parse(
            listOf(root(text(1) { copy(autofillHints = listOf("username"), textValue = "alice") }, text(2) { copy(autofillHints = listOf("password"), textValue = "s3cret") })),
        )
        assertEquals("alice", form.usernameValue)
        assertEquals("s3cret", form.passwordValue)
        assertTrue(!form.toString().contains("s3cret"))
    }

    @Test
    fun webDomainCanBeIgnored() {
        val page = root(
            text(1) { copy(htmlTag = "input", htmlAttributes = mapOf("type" to "email")) },
            FieldNode(webDomain = "evil.example", children = listOf(text(2) { copy(htmlTag = "input", htmlAttributes = mapOf("type" to "password")) })),
            webDomain = "bank.example",
        )
        val honoured = AutofillParser.parse(listOf(page))
        assertEquals("bank.example", honoured.webDomain)
        assertEquals(emptyList<Int>(), honoured.passwordIds) // iframe field excluded
        val ignored = AutofillParser.parse(listOf(page), useWebDomain = false)
        assertEquals(null, ignored.webDomain)
        assertEquals(listOf(2), ignored.passwordIds)
    }
}
