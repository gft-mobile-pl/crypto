package com.gft.crypto.domain.common.model

@Suppress("ClassName", "SpellCheckingInspection")
sealed interface SignaturePadding {
    object RSA_PKCS1: SignaturePadding
    object RSA_PSS : SignaturePadding
}