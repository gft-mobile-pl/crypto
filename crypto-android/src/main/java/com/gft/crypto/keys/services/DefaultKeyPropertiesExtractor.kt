package com.gft.crypto.keys.services

import android.security.keystore.KeyInfo
import com.gft.crypto.common.model.Algorithm
import com.gft.crypto.common.model.BlockMode
import com.gft.crypto.common.model.Digest
import com.gft.crypto.common.model.EncryptionPadding
import com.gft.crypto.common.model.SignaturePadding
import com.gft.crypto.common.model.Transformation
import com.gft.crypto.keys.model.KeyProperties
import com.gft.crypto.keys.model.KeyPurpose
import com.gft.crypto.keys.model.RandomizationPolicy
import com.gft.crypto.keys.model.UnlockPolicy
import com.gft.crypto.keys.model.UserAuthenticationPolicy
import java.security.Key
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import kotlin.time.DurationUnit
import kotlin.time.toDuration
import android.security.keystore.KeyProperties as NativeKeyProperties

class DefaultKeyPropertiesExtractor(
    private val keyStore: KeyStore
) : KeyPropertiesExtractor {

    override fun resolveKeyProperties(key: Key) = getKeyInfo(key)
        .let { keyInfo ->
            val keyPurposes = keyInfo.purposes.toKeyPurposes()
            KeyProperties(
                keySize = keyInfo.keySize,
                unlockPolicy = UnlockPolicy.Unknown,
                userAuthenticationPolicy = if (keyInfo.isUserAuthenticationRequired) {
                    when (keyInfo.userAuthenticationValidityDurationSeconds) {
                        0 -> UserAuthenticationPolicy.BiometricAuthenticationRequiredOnEachUse
                        Int.MAX_VALUE -> UserAuthenticationPolicy.RequiredAfterBoot
                        else -> UserAuthenticationPolicy.Required(keyInfo.userAuthenticationValidityDurationSeconds.toDuration(DurationUnit.SECONDS))
                    }
                } else {
                    UserAuthenticationPolicy.NotRequired
                },
                randomizationPolicy = RandomizationPolicy.Unknown,
                supportedTransformation = when (keyPurposes.first()) {
                    KeyPurpose.Decryption, KeyPurpose.Encryption -> Transformation.DataEncryption(
                        algorithm = key.algorithm.toKeyAlgorithm(),
                        blockMode = keyInfo.blockModes.toBlockModes().first(),
                        digest = keyInfo.digests.toDigests().first(),
                        padding = keyInfo.encryptionPaddings.toEncryptionPaddings().first()
                    )

                    KeyPurpose.SignatureVerification, KeyPurpose.Signing -> Transformation.MessageSigning(
                        algorithm = key.algorithm.toKeyAlgorithm(),
                        digest = keyInfo.digests.toDigests().first(),
                        padding = keyInfo.encryptionPaddings.toSignaturePaddings().firstOrNull() ?: SignaturePadding.NONE
                    )

                    KeyPurpose.Wrapping -> Transformation.KeyWrapping(
                        algorithm = key.algorithm.toKeyAlgorithm(),
                        blockMode = keyInfo.blockModes.toBlockModes().first(),
                        digest = keyInfo.digests.toDigests().first(),
                        padding = keyInfo.encryptionPaddings.toEncryptionPaddings().first()
                    )
                }
            )
        }

    private fun getKeyInfo(key: Key): KeyInfo = when (key) {
        is PrivateKey -> KeyFactory
            .getInstance(key.algorithm, keyStore.provider.name)
            .getKeySpec(key, KeyInfo::class.java)

        is SecretKey -> SecretKeyFactory
            .getInstance(key.algorithm, keyStore.provider.name)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo

        else -> {
            throw IllegalArgumentException("Unsupported key type!")
        }
    }
}

private fun Array<String>.toBlockModes() = map { blockMode ->
    when (blockMode) {
        NativeKeyProperties.BLOCK_MODE_ECB -> BlockMode.ECB
        NativeKeyProperties.BLOCK_MODE_CBC -> BlockMode.CBC
        NativeKeyProperties.BLOCK_MODE_CTR -> BlockMode.CTR
        NativeKeyProperties.BLOCK_MODE_GCM -> BlockMode.GCM
        else -> throw IllegalArgumentException("$blockMode block mode is not supported.")
    }
}

private fun Array<String>.toEncryptionPaddings() = map { padding ->
    when (padding) {
        NativeKeyProperties.ENCRYPTION_PADDING_NONE -> EncryptionPadding.NONE
        NativeKeyProperties.ENCRYPTION_PADDING_PKCS7 -> EncryptionPadding.PKCS7
        NativeKeyProperties.ENCRYPTION_PADDING_RSA_PKCS1 -> EncryptionPadding.PKCS1
        NativeKeyProperties.ENCRYPTION_PADDING_RSA_OAEP -> EncryptionPadding.OAEP
        else -> throw IllegalArgumentException("$padding encryption padding is not supported.")
    }
}

private fun Array<String>.toSignaturePaddings() = map { padding ->
    when (padding) {
        NativeKeyProperties.SIGNATURE_PADDING_RSA_PKCS1 -> SignaturePadding.PKCS1
        NativeKeyProperties.SIGNATURE_PADDING_RSA_PSS -> SignaturePadding.PSS
        else -> throw IllegalArgumentException("$padding signature padding is not supported.")
    }
}

private fun Array<String>.toDigests() = map { digest ->
    when (digest) {
        NativeKeyProperties.DIGEST_NONE -> Digest.NONE
        NativeKeyProperties.DIGEST_MD5 -> Digest.MD5
        NativeKeyProperties.DIGEST_SHA1 -> Digest.SHA_1
        NativeKeyProperties.DIGEST_SHA224 -> Digest.SHA_224
        NativeKeyProperties.DIGEST_SHA256 -> Digest.SHA_256
        NativeKeyProperties.DIGEST_SHA384 -> Digest.SHA_384
        NativeKeyProperties.DIGEST_SHA512 -> Digest.SHA_512
        else -> throw IllegalArgumentException("$digest digest is not supported.")
    }
}

private fun Int.toKeyPurposes(): Set<KeyPurpose> {
    val result = mutableSetOf<KeyPurpose>()
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_WRAP_KEY)) result.add(KeyPurpose.Wrapping) // placement of this check is important as wrapping a locally created key requires PURPOSE_DECRYPT as well
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_DECRYPT)) result.add(KeyPurpose.Decryption)
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_ENCRYPT)) result.add(KeyPurpose.Encryption)
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_VERIFY)) result.add(KeyPurpose.SignatureVerification)
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_SIGN)) result.add(KeyPurpose.Signing)
    return result
}

private fun String.toKeyAlgorithm() = when (this) {
    android.security.keystore.KeyProperties.KEY_ALGORITHM_AES -> Algorithm.AES
    android.security.keystore.KeyProperties.KEY_ALGORITHM_RSA -> Algorithm.RSA
    android.security.keystore.KeyProperties.KEY_ALGORITHM_EC -> Algorithm.ECDSA
    else -> throw IllegalArgumentException("$this algorithm is not a supported.")
}

private fun Int.hasFlag(flag: Int) = (this and flag) == flag
