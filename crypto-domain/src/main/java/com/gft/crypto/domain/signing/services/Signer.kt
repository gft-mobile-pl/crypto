package com.gft.crypto.domain.signing.services

import com.gft.crypto.domain.common.model.CryptographicOperation
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.keys.model.KeyAlias
import java.security.PrivateKey
import java.security.Signature

interface Signer {
    fun sign(alias: KeyAlias<Transformation.MessageSigning>, data: ByteArray): CryptographicOperation<Signature, ByteArray>
    fun sign(
        key: PrivateKey,
        transformation: Transformation.MessageSigning,
        data: ByteArray
    ): CryptographicOperation<Signature, ByteArray>
}
