package com.gft.crypto.domain.keys.model

import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.SecretKey

enum class KeyType {
    PUBLIC,
    PRIVATE,
    SECRET;

    fun toCipherType() = when (this) {
        PUBLIC -> Cipher.PUBLIC_KEY
        PRIVATE -> Cipher.PRIVATE_KEY
        SECRET -> Cipher.SECRET_KEY
    }

    companion object {
        fun valueOf(key: Key) = when (key) {
            is PublicKey -> PUBLIC
            is PrivateKey -> PRIVATE
            is SecretKey -> SECRET
            else -> throw IllegalArgumentException("$key is not a supported type!")
        }
    }
}
