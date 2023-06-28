package com.gft.crypto.domain.common.model

sealed interface Algorithm {
    object AES : Algorithm
    object RSA : Algorithm
}