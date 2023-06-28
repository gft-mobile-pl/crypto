package com.gft.crypto.domain.common.model

sealed interface EncryptionPadding {
    object None : EncryptionPadding
    object Pkcs7 : EncryptionPadding
    object RSAPkcs1 : EncryptionPadding
    object RSAOaep : EncryptionPadding
}