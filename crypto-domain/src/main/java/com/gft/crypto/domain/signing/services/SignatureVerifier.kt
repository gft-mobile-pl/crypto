package com.gft.crypto.domain.signing.services

import com.gft.crypto.domain.common.model.CryptographicOperation
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.keys.model.KeyAlias
import com.gft.crypto.domain.signing.model.SignatureVerificationResult
import java.security.PublicKey
import java.security.Signature

interface SignatureVerifier {
    fun verify(
        alias: KeyAlias<Transformation.MessageSigning>,
        signedData: ByteArray,
        signatureToVerify: ByteArray
    ): CryptographicOperation<Signature, SignatureVerificationResult>

    fun verify(
        publicKey: PublicKey,
        transformation: Transformation.MessageSigning,
        signedData: ByteArray,
        signatureToVerify: ByteArray
    ): CryptographicOperation<Signature, SignatureVerificationResult>
}
