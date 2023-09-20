package com.gft.crypto.framework.signing.services

import com.gft.crypto.domain.common.model.CryptographicOperation
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.keys.model.KeyAlias
import com.gft.crypto.domain.keys.repositories.KeysRepository
import com.gft.crypto.domain.signing.model.SignatureVerificationResult
import com.gft.crypto.domain.signing.model.SignatureVerificationResult.NOT_VALID
import com.gft.crypto.domain.signing.model.SignatureVerificationResult.VALID
import com.gft.crypto.domain.signing.services.SignatureVerifier
import com.gft.crypto.domain.signing.services.Signer
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

class DefaultSigner(private val keysRepository: KeysRepository) : Signer, SignatureVerifier {

    override fun sign(alias: KeyAlias<Transformation.MessageSigning>, data: ByteArray): CryptographicOperation<Signature, ByteArray> {
        val keyContainer = keysRepository.getKey(alias)
            .first { keyContainer ->
                keyContainer.key is PrivateKey
            }
        return signWithKey(keyContainer.key as PrivateKey, keyContainer.properties.supportedTransformation, data)
    }

    override fun sign(
        key: PrivateKey,
        transformation: Transformation.MessageSigning,
        data: ByteArray
    ): CryptographicOperation<Signature, ByteArray> = signWithKey(key, transformation, data)

    private fun signWithKey(key: PrivateKey, transformation: Transformation.MessageSigning, data: ByteArray) =
        object : CryptographicOperation<Signature, ByteArray> {
            override val processor: Signature = Signature.getInstance(transformation.canonicalTransformation).apply {
                initSign(key)
                update(data)
            }

            override fun perform(): ByteArray {
                return processor.sign()
            }
        }

    override fun verify(
        alias: KeyAlias<Transformation.MessageSigning>,
        signedData: ByteArray,
        signatureToVerify: ByteArray
    ): CryptographicOperation<Signature, SignatureVerificationResult> {
        val keyContainer = keysRepository.getKey(alias)
            .first { keyContainer ->
                keyContainer.key is PublicKey
            }
        return verifyWithKey(keyContainer.key as PublicKey, keyContainer.properties.supportedTransformation, signedData, signatureToVerify)
    }

    override fun verify(
        publicKey: PublicKey,
        transformation: Transformation.MessageSigning,
        signedData: ByteArray,
        signatureToVerify: ByteArray
    ) = verifyWithKey(publicKey, transformation, signedData, signatureToVerify)

    private fun verifyWithKey(
        key: PublicKey,
        transformation: Transformation.MessageSigning,
        signedData: ByteArray,
        signatureToVerify: ByteArray
    ) = object : CryptographicOperation<Signature, SignatureVerificationResult> {
        override val processor: Signature = Signature.getInstance(transformation.canonicalTransformation).apply {
            initVerify(key)
            update(signedData)
        }

        override fun perform(): SignatureVerificationResult {
            return if (processor.verify(signatureToVerify)) {
                VALID
            } else {
                NOT_VALID
            }
        }
    }
}
