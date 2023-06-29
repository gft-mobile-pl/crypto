package com.gft.crypto.domain.common.model

sealed interface Padding

enum class EncryptionPadding : Padding {
    None,
    PKSC7,
    RSA_PKCS1,
    RSA_OAEP
}

enum class SignaturePadding : Padding {
    RSA_PKCS1,
    RSA_PSS
}
