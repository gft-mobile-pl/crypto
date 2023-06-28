package com.gft.crypto.domain.common.model

@Suppress("SpellCheckingInspection", "ClassName")
sealed interface EncryptionPadding {
    object None : EncryptionPadding
    object PKSC7 : EncryptionPadding
    object RSA_PKCS1 : EncryptionPadding
    object RSA_OAEP : EncryptionPadding
}