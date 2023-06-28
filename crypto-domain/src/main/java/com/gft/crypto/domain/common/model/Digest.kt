package com.gft.crypto.domain.common.model

@Suppress("ClassName")
sealed interface Digest {
    object SHA_256 : Digest
    object SHA_384 : Digest
    object SHA_512 : Digest
}