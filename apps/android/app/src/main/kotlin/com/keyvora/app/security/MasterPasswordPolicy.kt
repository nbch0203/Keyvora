package com.keyvora.app.security

import java.text.Normalizer

/**
 * UI-side mirror of the core's master-password length rule (vault-core `MIN_MASTER_LEN` = 12 characters after NFC).
 * The core enforces it anyway (`VALIDATION` / `masterPassword`); this only gives immediate feedback.
 */
object MasterPasswordPolicy {
    const val MIN_LENGTH = 12
    const val RECOMMENDED_LENGTH = 16

    enum class Problem { TOO_SHORT, MISMATCH }

    /** Length in characters (code points) after NFC, as the core counts it. */
    fun length(password: String): Int {
        val n = Normalizer.normalize(password, Normalizer.Form.NFC)
        return n.codePointCount(0, n.length)
    }

    fun validate(password: String, confirm: String): Problem? = when {
        length(password) < MIN_LENGTH -> Problem.TOO_SHORT
        password != confirm -> Problem.MISMATCH
        else -> null
    }

    fun hint(password: String): String {
        val len = length(password)
        return when {
            password.isEmpty() -> "Mínimo $MIN_LENGTH caracteres. Mejor una frase de varias palabras ($RECOMMENDED_LENGTH o más)."
            len < MIN_LENGTH -> "Demasiado corta: $len de $MIN_LENGTH caracteres como mínimo."
            len < RECOMMENDED_LENGTH -> "Válida. Más larga ($RECOMMENDED_LENGTH o más) es más difícil de adivinar."
            else -> "Longitud adecuada."
        }
    }

    fun message(problem: Problem): String = when (problem) {
        Problem.TOO_SHORT -> "La contraseña maestra debe tener al menos $MIN_LENGTH caracteres."
        Problem.MISMATCH -> "Las contraseñas no coinciden."
    }
}
