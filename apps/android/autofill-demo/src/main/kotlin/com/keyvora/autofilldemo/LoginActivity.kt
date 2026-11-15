package com.keyvora.autofilldemo

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** Minimal login form (test-only) whose fields declare autofill hints. */
class LoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (24 * resources.displayMetrics.density).toInt()
        val user = EditText(this).apply {
            hint = "Usuario"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
            contentDescription = "username"
        }
        val pass = EditText(this).apply {
            hint = "Contraseña"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
            contentDescription = "password"
        }
        val status = TextView(this).apply { contentDescription = "status" }
        val login = Button(this).apply {
            text = "Entrar"
            // Shows only lengths, never the values (the test checks that the fill happened).
            setOnClickListener { status.text = "user=${user.text.length} pass=${pass.text.length}" }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 3, pad, pad)
            addView(TextView(this@LoginActivity).apply { text = "Demo de autorrelleno (solo pruebas)" })
            addView(user); addView(pass); addView(login); addView(status)
        })
    }
}
