package com.gft.crypto.framework.encryption.services

import com.gft.crypto.common.model.BlockMode
import com.gft.crypto.common.model.CryptographicOperation
import com.gft.crypto.common.model.EncryptionPadding
import com.gft.crypto.common.model.Transformation.DataEncryption
import com.gft.crypto.encryption.model.EncryptedData
import com.gft.crypto.encryption.model.IvParam
import com.gft.crypto.encryption.services.DataCipher
import com.gft.crypto.keys.model.KeyAlias
import com.gft.crypto.keys.repositories.KeysRepository
import java.io.Serializable
import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

private const val MGF1_DIGEST = "MGF1"
private const val AUTH_TAG_LENGTH = 128

class DefaultDataCipher(
    private val keysRepository: KeysRepository
) : DataCipher {
    override fun encrypt(alias: KeyAlias<DataEncryption>, data: ByteArray): CryptographicOperation<Cipher, EncryptedData> {
        val keyContainer = keysRepository.getKey(alias)
            .first { keyContainer ->
                keyContainer.key is PublicKey || keyContainer.key is SecretKey
            }
        return encryptWithKey(keyContainer.key, keyContainer.properties.supportedTransformation, data)
    }

    override fun encrypt(key: SecretKey, transformation: DataEncryption, data: ByteArray): CryptographicOperation<Cipher, EncryptedData> =
        encryptWithKey(key, transformation, data)

    override fun encrypt(key: PublicKey, transformation: DataEncryption, data: ByteArray): CryptographicOperation<Cipher, EncryptedData> =
        encryptWithKey(key, transformation, data)

    private fun encryptWithKey(key: Key, transformation: DataEncryption, data: ByteArray) = object :
        CryptographicOperation<Cipher, EncryptedData> {
        override val processor: Cipher = createCipher(key, transformation, Cipher.ENCRYPT_MODE, null)

        override fun perform(): EncryptedData {
            val encryptedBytes = processor.doFinal(data)
            return EncryptedData(
                data = encryptedBytes,
                algorithmParams = processor.iv?.let { iv -> IvParam(iv) }
            )
        }
    }

    override fun decrypt(alias: KeyAlias<DataEncryption>, encryptedData: EncryptedData): CryptographicOperation<Cipher, ByteArray> {
        val keyContainer = keysRepository.getKey(alias)
            .first { keyContainer ->
                keyContainer.key is PrivateKey || keyContainer.key is SecretKey
            }
        return decryptWithKey(keyContainer.key, keyContainer.properties.supportedTransformation, encryptedData)
    }

    override fun decrypt(key: SecretKey, transformation: DataEncryption, encryptedData: EncryptedData): CryptographicOperation<Cipher, ByteArray> =
        decryptWithKey(key, transformation, encryptedData)

    override fun decrypt(key: PrivateKey, transformation: DataEncryption, encryptedData: EncryptedData): CryptographicOperation<Cipher, ByteArray> =
        decryptWithKey(key, transformation, encryptedData)

    private fun decryptWithKey(key: Key, transformation: DataEncryption, encryptedData: EncryptedData) = object :
        CryptographicOperation<Cipher, ByteArray> {
        override val processor: Cipher = createCipher(
            key = key,
            transformation = transformation,
            mode = Cipher.DECRYPT_MODE,
            params = encryptedData.algorithmParams
        )

        override fun perform(): ByteArray = processor.doFinal(encryptedData.data)
    }

    private fun createCipher(key: Key, transformation: DataEncryption, mode: Int, params: Serializable?): Cipher {
        val cipher = Cipher.getInstance(transformation.canonicalTransformation)
            .apply {
                val parameterSpec = when (params) {
                    is IvParam -> when (transformation.blockMode) {
                        BlockMode.GCM -> GCMParameterSpec(AUTH_TAG_LENGTH, params.iv)
                        BlockMode.CBC, BlockMode.CTR -> IvParameterSpec(params.iv)
                        else -> throw IllegalArgumentException("Using IV with ${transformation.blockMode} is not supported.")
                    }

                    else -> null
                }
                if (parameterSpec != null) init(mode, key, parameterSpec)
                else init(mode, key)
            }
        return when (transformation.padding) {
            EncryptionPadding.OAEP,
            EncryptionPadding.OAEP_SHA_1_MGF1,
            EncryptionPadding.OAEP_SHA_224_MGF1,
            EncryptionPadding.OAEP_SHA_256_MGF1,
            EncryptionPadding.OAEP_SHA_384_MGF1,
            EncryptionPadding.OAEP_SHA_512_MGF1 -> {
                val oaepParameterSpec = OAEPParameterSpec(
                    cipher.parameters.getParameterSpec(OAEPParameterSpec::class.java).digestAlgorithm,
                    MGF1_DIGEST,
                    // Android KeyStore always uses SHA1 for MGF1 digest;
                    // refer to: https://developer.android.com/guide/topics/security/cryptography#oaep-mgf1-digest
                    MGF1ParameterSpec.SHA1,
                    PSource.PSpecified.DEFAULT
                )
                Cipher.getInstance(transformation.canonicalTransformation)
                    .apply {
                        init(mode, key, oaepParameterSpec)
                    }
            }

            else -> cipher
        }
    }
}
