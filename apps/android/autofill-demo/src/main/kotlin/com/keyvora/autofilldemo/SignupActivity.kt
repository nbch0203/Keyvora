package com.keyvora.autofilldemo

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Minimal sign-up form (test-only): username + new password + confirmation, with the `newPassword` hint, to exercise
 * Keyvora's «Generar contraseña segura» suggestion.
 * Launch: adb shell am start -n com.keyvora.autofilldemo/.SignupActivity
 */
class SignupActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (24 * resources.displayMetrics.density).toInt()
        fun field(label: String, desc: String, hint: String, password: Boolean) = EditText(this).apply {
            this.hint = label
            inputType = InputType.TYPE_CLASS_TEXT or
                if (password) InputType.TYPE_TEXT_VARIATION_PASSWORD else InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            setAutofillHints(hint)
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
            contentDescription = desc
        }
        val user = field("Correo", "username", View.AUTOFILL_HINT_EMAIL_ADDRESS, password = false)
        val pass = field("Contraseña nueva", "new_password", "newPassword", password = true)
        val again = field("Repite la contraseña", "confirm_password", "newPassword", password = true)
        val status = TextView(this).apply { contentDescription = "status" }
        val create = Button(this).apply {
            text = "Crear cuenta"
            // Only lengths and whether both passwords match: never the values.
            setOnClickListener {
                status.text = "user=${user.text.length} pass=${pass.text.length} match=${pass.text.toString() == again.text.toString()}"
            }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 3, pad, pad)
            addView(TextView(this@SignupActivity).apply { text = "Demo de registro (solo pruebas)" })
            addView(user); addView(pass); addView(again); addView(create); addView(status)
        })
    }
}
