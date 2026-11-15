package com.keyvora.app.autofill

import com.keyvora.app.autofill.AutofillParser.TYPE_CLASS_NUMBER
import com.keyvora.app.autofill.AutofillParser.TYPE_CLASS_TEXT
import com.keyvora.app.autofill.AutofillParser.TYPE_NUMBER_VARIATION_PASSWORD
import com.keyvora.app.autofill.AutofillParser.TYPE_TEXT_VARIATION_PASSWORD
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Sign-up detection and the «Generar contraseña segura» suggestion. */
class AutofillGenerateTest {
    private fun user(id: Int) = FieldNode(id = id, isTextField = true, inputType = TYPE_CLASS_TEXT, autofillHints = listOf("username"))
    private fun pwd(id: Int, vararg hints: String, idEntry: String? = null) =
        FieldNode(id = id, isTextField = true, inputType = TYPE_CLASS_TEXT or TYPE_TEXT_VARIATION_PASSWORD, autofillHints = hints.toList(), idEntry = idEntry)
    private fun html(id: Int, vararg attrs: Pair<String, String>) =
        FieldNode(id = id, isTextField = true, htmlTag = "input", htmlAttributes = attrs.toMap())
    private fun pin(id: Int) = FieldNode(id = id, isTextField = true, inputType = TYPE_CLASS_NUMBER or TYPE_NUMBER_VARIATION_PASSWORD)
    private fun form(vararg fields: FieldNode<Int>) = AutofillParser.parse(listOf(FieldNode(children = fields.toList())))

    @Test
    fun loginFormIsNotSignup() {
        val f = form(user(1), pwd(2, "password"))
        assertFalse(f.isSignup)
        assertEquals(listOf(2), f.generatedPasswordIds)
        assertFalse("app login: never", AutofillGenerate.shouldOffer(f, isWeb = false, savedMatches = 0))
        assertFalse("web login with saved entries: no", AutofillGenerate.shouldOffer(f, isWeb = true, savedMatches = 1))
        assertTrue("web page with nothing saved yet: yes", AutofillGenerate.shouldOffer(f, isWeb = true, savedMatches = 0))
    }

    @Test
    fun newPasswordHintsMarkSignup() {
        val native = form(user(1), pwd(2, "newPassword"))
        assertTrue(native.isSignup)
        assertEquals(listOf(2), native.newPasswordIds)
        assertTrue(AutofillGenerate.shouldOffer(native, isWeb = false, savedMatches = 0))
        assertTrue("sign-up also when entries exist (second account)", AutofillGenerate.shouldOffer(native, isWeb = true, savedMatches = 3))

        val web = form(html(1, "type" to "email"), html(2, "type" to "password", "autocomplete" to "new-password"))
        assertTrue(web.isSignup)
        assertEquals(listOf(2), web.generatedPasswordIds)
    }

    @Test
    fun passwordAndConfirmationAreBothFilled() {
        // Only the confirmation is recognisable by its name: both fields must still get the password.
        val f = form(user(1), pwd(2), pwd(3, idEntry = "confirm_password"))
        assertTrue(f.isSignup)
        assertEquals(listOf(2, 3), f.generatedPasswordIds)
        val plain = form(user(1), pwd(2), pwd(3))
        assertTrue("two password fields → sign-up", plain.isSignup)
        assertEquals(listOf(2, 3), plain.generatedPasswordIds)
        val single = form(user(1), pwd(2, idEntry = "register_password"))
        assertTrue("one field named like sign-up", single.isSignup)
        assertTrue(AutofillGenerate.shouldOffer(single, isWeb = false, savedMatches = 0))
    }

    @Test
    fun changePasswordFillsOnlyTheNewFields() {
        val f = form(
            html(1, "type" to "password", "autocomplete" to "current-password", "name" to "old"),
            html(2, "type" to "password", "autocomplete" to "new-password"),
            html(3, "type" to "password", "autocomplete" to "new-password"),
        )
        assertEquals(listOf(2, 3), f.generatedPasswordIds)
        // Native change-password screen: "old" + new + confirmation, no hints.
        val native = form(pwd(1, idEntry = "old_password"), pwd(2, idEntry = "new_password"), pwd(3, idEntry = "repeat_password"))
        assertEquals(listOf(2, 3), native.generatedPasswordIds)
    }

    @Test
    fun numericPinsNeverGetAGeneratedPassword() {
        val lockScreen = form(pin(1), pin(2))
        assertTrue(lockScreen.isSignup)
        assertTrue(lockScreen.generatedPasswordIds.isEmpty())
        assertFalse(AutofillGenerate.shouldOffer(lockScreen, isWeb = false, savedMatches = 0))
        val webPin = form(html(1, "type" to "password", "inputmode" to "numeric", "autocomplete" to "new-password"))
        assertFalse(AutofillGenerate.shouldOffer(webPin, isWeb = true, savedMatches = 0))
    }

    @Test
    fun nothingToFillNothingOffered() {
        val f = form(user(1))
        assertFalse(AutofillGenerate.shouldOffer(f, isWeb = true, savedMatches = 0))
    }
}
