package com.keyvora.app.core

/** Core build: backed by the generated UniFFI bindings (package uniffi.keyvora_ffi) and libkeyvora_ffi.so. */
object CoreBridgeFactory {
    fun create(): CoreBridge = UniffiCoreBridge
}
