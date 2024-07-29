package com.gft.crypto.signing.services

import com.gft.crypto.common.model.CryptographicOperation
import com.gft.crypto.common.model.Transformation
import com.gft.crypto.keys.model.KeyAlias
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
