package com.gft.crypto.domain.common.model

sealed interface SignaturePadding {
    object RSAPkcs1: SignaturePadding
    object RSAPss : SignaturePadding
}