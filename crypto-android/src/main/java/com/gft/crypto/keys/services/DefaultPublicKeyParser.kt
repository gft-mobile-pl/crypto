package com.gft.crypto.keys.services

import com.gft.crypto.common.model.Algorithm
import com.gft.crypto.keys.utils.toNativeKeyAlgorithm
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class DefaultPublicKeyParser : PublicKeyParser {

    override fun parse(publicKeyPem: String, algorithm: Algorithm): PublicKey {
        val encodedKey = publicKeyPem
            .replace(Regex(PEM_BOUNDARY_PATTERN), "")
            .filter { char -> !char.isWhitespace() }

        val decodedKey = Base64.getDecoder().decode(encodedKey)
        val spec = X509EncodedKeySpec(decodedKey)
        val keyFactory = KeyFactory.getInstance(algorithm.toNativeKeyAlgorithm())
        return keyFactory.generatePublic(spec)
    }
}

private const val PEM_BOUNDARY_PATTERN = "\\-.+\\-"
