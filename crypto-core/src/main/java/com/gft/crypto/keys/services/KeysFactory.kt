package com.gft.crypto.keys.services

import com.gft.crypto.common.model.Algorithm
import com.gft.crypto.common.model.Transformation
import java.security.Key
import java.security.KeyPairGenerator
import javax.crypto.KeyGenerator

class KeysFactory {
    fun <T : Transformation> generateKey(keySize: Int, supportedTransformation: T): Set<Key> = when (supportedTransformation.algorithm) {
        Algorithm.RSA,
        Algorithm.ECDSA -> {
            KeyPairGenerator
                .getInstance(supportedTransformation.algorithm.name)
                .apply {
                    initialize(keySize)
                }
                .generateKeyPair()
                .let { keyPair ->
                    setOf(keyPair.public, keyPair.private)
                }
        }

        else -> {
            KeyGenerator
                .getInstance(supportedTransformation.algorithm.name)
                .apply {
                    init(keySize)
                }
                .generateKey()
                .let { secretKey ->
                    setOf(secretKey)
                }
        }
    }
}
