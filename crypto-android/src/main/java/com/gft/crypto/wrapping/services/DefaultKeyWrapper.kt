package com.gft.crypto.wrapping.services

import android.security.keystore.KeyProperties
import com.gft.crypto.common.model.Algorithm
import com.gft.crypto.common.model.BlockMode
import com.gft.crypto.common.model.CryptographicOperation
import com.gft.crypto.common.model.EncryptionPadding
import com.gft.crypto.common.model.Transformation
import com.gft.crypto.encryption.model.IvParam
import com.gft.crypto.keys.model.KeyAlias
import com.gft.crypto.keys.model.KeyType
import com.gft.crypto.keys.repositories.KeysRepository
import com.gft.crypto.wrapping.model.WrappedKeyContainer
import com.gft.crypto.keys.utils.toNativeKeyAlgorithm
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

class DefaultKeyWrapper(
    private val keysRepository: KeysRepository
) : KeyWrapper {
    override fun wrap(alias: KeyAlias<Transformation.KeyWrapping>, keyToWrap: Key): CryptographicOperation<Cipher, WrappedKeyContainer> {
        val keyContainer = keysRepository.getKey(alias)
            .first { keyContainer ->
                keyContainer.key is PublicKey || keyContainer.key is SecretKey
            }
        return wrapWithKey(keyContainer.key, keyContainer.properties.supportedTransformation, keyToWrap)
    }

    override fun wrap(key: SecretKey, transformation: Transformation.KeyWrapping, keyToWrap: Key) = wrapWithKey(key, transformation, keyToWrap)

    override fun wrap(key: PublicKey, transformation: Transformation.KeyWrapping, keyToWrap: Key) = wrapWithKey(key, transformation, keyToWrap)

    private fun wrapWithKey(key: Key, transformation: Transformation.KeyWrapping, keyToWrap: Key) = object :
        CryptographicOperation<Cipher, WrappedKeyContainer> {
        override val processor: Cipher = createCipher(key, transformation, Cipher.WRAP_MODE, null)
        override fun perform(): WrappedKeyContainer {
            val wrappedKeyBytes = processor.wrap(keyToWrap)
            return WrappedKeyContainer(
                wrappedKeyBytes = wrappedKeyBytes,
                wrappedKeyAlgorithm = key.algorithm.toCanonicalAlgorithm(),
                wrappedKeyType = KeyType.valueOf(keyToWrap),
                wrappingAlgorithmParams = processor.iv?.let { iv -> IvParam(iv) }
            )
        }
    }

    override fun unwrap(alias: KeyAlias<Transformation.KeyWrapping>, wrappedKeyData: WrappedKeyContainer): CryptographicOperation<Cipher, Key> {
        val keyContainer = keysRepository.getKey(alias)
            .first { keyContainer ->
                keyContainer.key is PrivateKey || keyContainer.key is SecretKey
            }
        return unwrapWithKey(keyContainer.key, keyContainer.properties.supportedTransformation, wrappedKeyData)
    }

    override fun unwrap(key: SecretKey, transformation: Transformation.KeyWrapping, wrappedKeyData: WrappedKeyContainer) =
        unwrapWithKey(key, transformation, wrappedKeyData)

    override fun unwrap(key: PrivateKey, transformation: Transformation.KeyWrapping, wrappedKeyData: WrappedKeyContainer) =
        unwrapWithKey(key, transformation, wrappedKeyData)

    private fun unwrapWithKey(
        key: Key,
        transformation: Transformation.KeyWrapping,
        wrappedKeyData: WrappedKeyContainer
    ) = object : CryptographicOperation<Cipher, Key> {
        override val processor: Cipher = createCipher(
            key = key,
            transformation = transformation,
            mode = Cipher.UNWRAP_MODE,
            params = wrappedKeyData.wrappingAlgorithmParams
        )

        override fun perform(): Key = processor.unwrap(
            wrappedKeyData.wrappedKeyBytes,
            wrappedKeyData.wrappedKeyAlgorithm.toNativeKeyAlgorithm(),
            wrappedKeyData.wrappedKeyType.toCipherType()
        )
    }

    private fun createCipher(key: Key, transformation: Transformation.KeyWrapping, mode: Int, params: Serializable?): Cipher {
        val cipher = Cipher.getInstance(transformation.canonicalTransformation)
            .apply {
                @Suppress("DEPRECATION")
                val parameterSpec = when (params) {
                    is IvParam -> when (transformation.blockMode) {
                        BlockMode.GCM -> GCMParameterSpec(AUTH_TAG_LENGTH, params.iv)
                        BlockMode.CBC, BlockMode.CTR -> IvParameterSpec(params.iv)
                        else -> throw IllegalArgumentException("Using IV with ${transformation.blockMode} is not supported.")
                    }
                    is com.gft.crypto.domain.encryption.model.IvParam -> when (transformation.blockMode) {
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

fun String.toCanonicalAlgorithm() = when (this) {
    KeyProperties.KEY_ALGORITHM_EC -> Algorithm.ECDSA
    else -> Algorithm.valueOf(this)
}
