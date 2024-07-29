package com.gft.crypto.signing.services

import com.gft.crypto.common.model.CryptographicOperation
import com.gft.crypto.common.model.Transformation
import com.gft.crypto.keys.model.KeyAlias
import com.gft.crypto.signing.model.SignatureVerificationResult
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
