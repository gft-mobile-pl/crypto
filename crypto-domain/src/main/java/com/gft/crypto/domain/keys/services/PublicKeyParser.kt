package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.common.model.Algorithm
import java.security.PublicKey

interface PublicKeyParser {

    fun parse(publicKeyPem: String, algorithm: Algorithm): PublicKey
}
