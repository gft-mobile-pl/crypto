package com.gft.crypto.domain.common.model

sealed interface Digest {
    object SHA256 : Digest
    object SHA384 : Digest
    object SHA512 : Digest
}