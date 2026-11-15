package com.keyvora.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MasterPasswordPolicyTest {
    @Test
    fun minimumIsTwelveCharacters() {
        assertEquals(12, MasterPasswordPolicy.MIN_LENGTH)
        assertEquals(MasterPasswordPolicy.Problem.TOO_SHORT, MasterPasswordPolicy.validate("a".repeat(11), "a".repeat(11)))
        assertNull(MasterPasswordPolicy.validate("a".repeat(12), "a".repeat(12)))
        assertEquals(MasterPasswordPolicy.Problem.MISMATCH, MasterPasswordPolicy.validate("a".repeat(12), "b".repeat(12)))
    }

    @Test
    fun lengthIsCountedAfterNfcLikeTheCore() {
        // "contraseña1" written with a combining tilde: 12 UTF-16 units / code points in NFD, 11 characters in NFC.
        val nfd = "contraseña1"
        assertEquals(12, nfd.length)
        assertEquals(11, MasterPasswordPolicy.length(nfd))
        assertEquals(MasterPasswordPolicy.Problem.TOO_SHORT, MasterPasswordPolicy.validate(nfd, nfd))
        // Emoji (surrogate pair) counts as one character.
        assertEquals(12, MasterPasswordPolicy.length("🔑" + "a".repeat(11)))
    }

    @Test
    fun hintsAreInSpanish() {
        assertTrue(MasterPasswordPolicy.hint("").contains("Mínimo 12"))
        assertTrue(MasterPasswordPolicy.hint("corta").contains("Demasiado corta"))
        assertTrue(MasterPasswordPolicy.hint("a".repeat(13)).startsWith("Válida"))
        assertEquals("Longitud adecuada.", MasterPasswordPolicy.hint("a".repeat(20)))
        assertTrue(MasterPasswordPolicy.message(MasterPasswordPolicy.Problem.TOO_SHORT).contains("12"))
    }
}
