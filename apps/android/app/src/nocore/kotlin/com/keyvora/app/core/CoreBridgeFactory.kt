package com.keyvora.app.core

/** No-core build: the UniFFI bindings were not generated (see apps/android/README.md). */
object CoreBridgeFactory {
    fun create(): CoreBridge = NoCoreBridge
}

internal object NoCoreBridge : CoreBridge {
    override val isAvailable: Boolean = false

    private fun missing(): Nothing = throw CoreException(CoreException.CORE_NOT_BUILT)

    override fun create(master: String, params: KdfParams, deviceId: String, nowMs: Long): VaultSession = missing()
    override fun unlockWithPassword(container: String, master: String, deviceId: String): VaultSession = missing()
    override fun unlockWithRecoveryKey(container: String, recoveryKey: String, deviceId: String): VaultSession = missing()
    override fun openWithDataKey(container: String, dek: ByteArray, deviceId: String): VaultSession = missing()
    override fun generatePassword(options: GeneratorOptions): String = missing()
    override fun passwordEntropyBits(options: GeneratorOptions): Double = missing()
    override fun defaultGeneratorOptions(): GeneratorOptions = GeneratorOptions()
    override fun defaultKdfParams(): KdfParams = missing()
    override fun matchLevel(entryUrl: String, pageUrl: String): MatchLevel = missing()
    override fun pageOrigin(pageUrl: String): String? = missing()
}
