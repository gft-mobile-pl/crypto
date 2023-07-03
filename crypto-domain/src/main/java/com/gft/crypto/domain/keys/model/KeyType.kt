package com.gft.crypto.domain.keys.model

import javax.crypto.Cipher

enum class KeyType {
    PUBLIC,
    PRIVATE,
    SECRET;

    internal fun toCipherType() = when(this) {
        PUBLIC -> Cipher.PUBLIC_KEY
        PRIVATE -> Cipher.PRIVATE_KEY
        SECRET -> Cipher.SECRET_KEY
    }
}
