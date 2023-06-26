package com.gft.crypto.domain.model

sealed interface KeyPurpose {
    object Encryption : KeyPurpose
    object Decryption : KeyPurpose
    object Signing : KeyPurpose
    object SignatureVerification : KeyPurpose
    object Wrapping : KeyPurpose
    object Unwrapping : KeyPurpose
}
