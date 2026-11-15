package com.keyvora.app.autofill

import com.keyvora.app.autofill.AutofillParser.TYPE_CLASS_NUMBER
import com.keyvora.app.autofill.AutofillParser.TYPE_CLASS_TEXT
import com.keyvora.app.autofill.AutofillParser.TYPE_NUMBER_VARIATION_PASSWORD
import com.keyvora.app.autofill.AutofillParser.TYPE_TEXT_VARIATION_PASSWORD
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Extra detection signals (Chrome predictions, labels, content descriptions) and the «Elegir una entrada» rule. */
class AutofillDetectionTest {
    private fun html(id: Int, vararg attrs: Pair<String, String>) =
        FieldNode(id = id, isTextField = true, htmlTag = "input", htmlAttributes = attrs.toMap())
    private fun text(id: Int, desc: String? = null, hint: String? = null) =
        FieldNode(id = id, isTextField = true, inputType = TYPE_CLASS_TEXT, contentDescription = desc, hint = hint)
    private fun pwd(id: Int) = FieldNode(id = id, isTextField = true, inputType = TYPE_CLASS_TEXT or TYPE_TEXT_VARIATION_PASSWORD)
    private fun pin(id: Int) = FieldNode(id = id, isTextField = true, inputType = TYPE_CLASS_NUMBER or TYPE_NUMBER_VARIATION_PASSWORD)
    private fun form(vararg fields: FieldNode<Int>) = AutofillParser.parse(listOf(FieldNode(children = fields.toList())))

    @Test
    fun chromePredictionsAreUsedWhenThePageHasNoHints() {
        // Plain type=text fields with meaningless names: only Chrome's predictions identify them.
        assertEquals(FieldType.USERNAME, AutofillParser.classify(html(1, "type" to "text", "name" to "f1", "computed-autofill-hints" to "USERNAME")))
        assertEquals(FieldType.USERNAME, AutofillParser.classify(html(1, "type" to "text", "name" to "f1", "crowdsourcing-autofill-hints" to "SINGLE_USERNAME")))
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(html(1, "type" to "text", "name" to "f2", "computed-autofill-hints" to "PASSWORD")))
        assertEquals(FieldType.NONE, AutofillParser.classify(html(1, "type" to "text", "name" to "user", "computed-autofill-hints" to "CREDIT_CARD_NUMBER")))
        assertEquals(FieldType.NONE, AutofillParser.classify(html(1, "type" to "text", "name" to "f3", "computed-autofill-hints" to "UNKNOWN_TYPE")))
        // A hidden input never becomes a field, whatever the prediction.
        assertEquals(FieldType.NONE, AutofillParser.classify(html(1, "type" to "hidden", "computed-autofill-hints" to "PASSWORD")))
    }

    @Test
    fun chromeSignupPredictionsMarkNewPasswords() {
        val f = form(
            html(1, "type" to "email"),
            html(2, "type" to "password", "computed-autofill-hints" to "ACCOUNT_CREATION_PASSWORD"),
            html(3, "type" to "password", "computed-autofill-hints" to "CONFIRMATION_PASSWORD"),
        )
        assertTrue(f.isSignup)
        assertEquals(listOf(2, 3), f.generatedPasswordIds)
    }

    @Test
    fun visibleLabelsAndPlaceholdersAreUsed() {
        assertEquals(FieldType.USERNAME, AutofillParser.classify(html(1, "type" to "text", "name" to "f1", "label" to "Correo electrónico o teléfono")))
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(html(1, "type" to "text", "name" to "f2", "placeholder" to "Contraseña")))
        assertEquals(FieldType.NONE, AutofillParser.classify(html(1, "type" to "text", "name" to "f3", "label" to "Código de cupón")))
    }

    @Test
    fun nativeContentDescriptionsAreUsed() {
        assertEquals(FieldType.USERNAME, AutofillParser.classify(text(1, desc = "Usuario")))
        assertEquals(FieldType.PASSWORD, AutofillParser.classify(text(1, desc = "Contraseña")))
        assertEquals(FieldType.NONE, AutofillParser.classify(text(1, desc = "Buscar")))
    }

    @Test
    fun pickIsOfferedOnlyOnAppLoginsWithoutLinkedEntries() {
        val login = form(text(1, hint = "Usuario"), pwd(2))
        assertTrue(AutofillPick.shouldOffer(login, isApp = true, savedMatches = 0))
        assertFalse("already linked", AutofillPick.shouldOffer(login, isApp = true, savedMatches = 1))
        assertFalse("web pages match by origin only", AutofillPick.shouldOffer(login, isApp = false, savedMatches = 0))
        val signup = form(text(1, hint = "Correo"), pwd(2), pwd(3))
        assertFalse("sign-up: generate instead", AutofillPick.shouldOffer(signup, isApp = true, savedMatches = 0))
        assertFalse("numeric PIN (lock screen)", AutofillPick.shouldOffer(form(pin(1)), isApp = true, savedMatches = 0))
        assertFalse("no password field", AutofillPick.shouldOffer(form(text(1, hint = "Correo")), isApp = true, savedMatches = 0))
    }
}
