package com.gft.crypto.keys.model

sealed interface KeyPurpose {
    object Encryption : KeyPurpose
    object Decryption : KeyPurpose
    object Signing : KeyPurpose
    object SignatureVerification : KeyPurpose
    object Wrapping : KeyPurpose
}
