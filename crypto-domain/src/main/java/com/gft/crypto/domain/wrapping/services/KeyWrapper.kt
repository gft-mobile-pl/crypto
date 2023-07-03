package com.gft.crypto.domain.wrapping.services

import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.CryptographicOperation
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.common.model.Transformation.KeyWrapping
import com.gft.crypto.domain.keys.model.KeyAlias
import com.gft.crypto.domain.keys.model.KeyType
import com.gft.crypto.domain.keys.repositories.KeysRepository
import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

private const val MGF1_DIGEST = "MGF1"
private const val IV_SEPARATOR = ":"
private const val AUTH_TAG_LENGTH = 128

class KeyWrapper(
    private val keysRepository: KeysRepository
) {
    fun wrap(alias: KeyAlias<KeyWrapping>, keyToWrap: Key): CryptographicOperation<Cipher, String> {
        val keyContainer = keysRepository.getKey(alias)
            .first { keyContainer ->
                keyContainer.key is PublicKey || keyContainer.key is SecretKey
            }
        return wrapWithKey(keyContainer.key, keyContainer.properties.supportedTransformation, keyToWrap)
    }

    fun wrap(key: SecretKey, transformation: KeyWrapping, keyToWrap: Key) = wrapWithKey(key, transformation, keyToWrap)

    fun wrap(key: PublicKey, transformation: KeyWrapping, keyToWrap: Key) = wrapWithKey(key, transformation, keyToWrap)

    private fun wrapWithKey(key: Key, transformation: KeyWrapping, keyToWrap: Key) = object : CryptographicOperation<Cipher, String> {
        override val processor: Cipher = createCipher(key, transformation, Cipher.WRAP_MODE, null)
        override fun perform(): String {
            val wrappedKeyBytes = processor.wrap(keyToWrap)
            var result = Base64.getEncoder().encodeToString(wrappedKeyBytes)
            if (transformation.algorithm == Algorithm.AES) {
                result += IV_SEPARATOR + Base64.getEncoder().encodeToString(processor.iv)
            }
            return result
        }
    }

    fun unwrap(alias: KeyAlias<KeyWrapping>, wrappedKey: String, algorithm: Algorithm, keyType: KeyType): CryptographicOperation<Cipher, Key> {
        val keyContainer = keysRepository.getKey(alias)
            .first { keyContainer ->
                keyContainer.key is PrivateKey || keyContainer.key is SecretKey
            }
        return unwrapWithKey(keyContainer.key, keyContainer.properties.supportedTransformation, wrappedKey, algorithm, keyType)
    }

    fun unwrap(key: SecretKey, transformation: KeyWrapping, wrappedKey: String, algorithm: Algorithm, keyType: KeyType) =
        unwrapWithKey(key, transformation, wrappedKey, algorithm, keyType)

    fun unwrap(key: PrivateKey, transformation: KeyWrapping, wrappedKey: String, algorithm: Algorithm, keyType: KeyType) =
        unwrapWithKey(key, transformation, wrappedKey, algorithm, keyType)

    private fun unwrapWithKey(
        key: Key,
        transformation: KeyWrapping,
        wrappedKey: String,
        algorithm: Algorithm,
        keyType: KeyType
    ) = object : CryptographicOperation<Cipher, Key> {
        private val wrappedKeyBytes: ByteArray
        private val ivBytes: ByteArray?

        init {
            if (transformation.algorithm == Algorithm.AES) {
                val dataChunks = wrappedKey.split(IV_SEPARATOR)
                wrappedKeyBytes = Base64.getDecoder().decode(dataChunks[0])
                ivBytes = Base64.getDecoder().decode(dataChunks[1])
            } else {
                wrappedKeyBytes = Base64.getDecoder().decode(wrappedKey)
                ivBytes = null
            }
        }

        override val processor: Cipher = createCipher(key, transformation, Cipher.UNWRAP_MODE, ivBytes)
        override fun perform(): Key = processor.unwrap(wrappedKeyBytes, algorithm.name, keyType.toCipherType())
    }

    private fun createCipher(key: Key, transformation: KeyWrapping, mode: Int, iv: ByteArray?): Cipher {
        val cipher = Cipher
            .getInstance(transformation.canonicalTransformation)
            .apply {
                val parameterSpec = iv?.let {
                    when (transformation.blockMode) {
                        BlockMode.GCM -> GCMParameterSpec(AUTH_TAG_LENGTH, iv)
                        BlockMode.CBC, BlockMode.CTR -> IvParameterSpec(iv)
                        else -> throw IllegalArgumentException("Using IV with ${transformation.blockMode} is not supported.")
                    }
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
                Cipher
                    .getInstance(transformation.canonicalTransformation)
                    .apply {
                        init(mode, key, oaepParameterSpec)
                    }
            }

            else -> cipher
        }
    }
}
