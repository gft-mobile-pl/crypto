package com.gft.crypto.keys.services

import com.gft.crypto.common.model.Algorithm
import java.security.PublicKey

interface PublicKeyParser {

    fun parse(publicKeyPem: String, algorithm: Algorithm): PublicKey
}
