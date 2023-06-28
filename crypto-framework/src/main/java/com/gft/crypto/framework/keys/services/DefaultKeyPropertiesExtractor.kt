package com.gft.crypto.framework.keys.services

import android.security.keystore.KeyInfo
import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.CryptographicOperationParams
import com.gft.crypto.domain.common.model.Digest
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.common.model.SignaturePadding
import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.keys.model.KeyPurpose
import com.gft.crypto.domain.keys.model.UnlockPolicy
import com.gft.crypto.domain.keys.model.UserAuthenticationPolicy
import com.gft.crypto.domain.keys.services.KeyPropertiesExtractor
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
            KeyProperties(
                keySize = keyInfo.keySize,
                purposes = keyInfo.purposes.toKeyPurposes(),
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
                supportedOperationParams = CryptographicOperationParams(
                    algorithm = key.algorithm.toKeyAlgorithm(),
                    digests = keyInfo.digests.toDigests(),
                    signaturePaddings = keyInfo.signaturePaddings.toSignaturePaddings(),
                    encryptionPaddings = keyInfo.encryptionPaddings.toEncryptionPaddings(),
                    blockModes = keyInfo.blockModes.toBlockModes()
                )
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

private fun Array<String>.toBlockModes() = firstOrNull()?.let { blockMode ->
    when (blockMode) {
        NativeKeyProperties.BLOCK_MODE_ECB -> BlockMode.ECB
        NativeKeyProperties.BLOCK_MODE_CBC -> BlockMode.CBC
        NativeKeyProperties.BLOCK_MODE_CTR -> BlockMode.CTR
        NativeKeyProperties.BLOCK_MODE_GCM -> BlockMode.GCM
        else -> throw IllegalArgumentException("$blockMode block mode is not supported.")
    }
}

private fun Array<String>.toEncryptionPaddings() = firstOrNull()?.let { padding ->
    when (padding) {
        NativeKeyProperties.ENCRYPTION_PADDING_NONE -> EncryptionPadding.None
        NativeKeyProperties.ENCRYPTION_PADDING_PKCS7 -> EncryptionPadding.PKSC7
        NativeKeyProperties.ENCRYPTION_PADDING_RSA_PKCS1 -> EncryptionPadding.RSA_PKCS1
        NativeKeyProperties.ENCRYPTION_PADDING_RSA_OAEP -> EncryptionPadding.RSA_OAEP
        else -> throw IllegalArgumentException("$padding encryption padding is not supported.")
    }
}

private fun Array<String>.toSignaturePaddings() = firstOrNull()?.let { padding ->
    when (padding) {
        NativeKeyProperties.SIGNATURE_PADDING_RSA_PKCS1 -> SignaturePadding.RSA_PKCS1
        NativeKeyProperties.SIGNATURE_PADDING_RSA_PSS -> SignaturePadding.RSA_PSS
        else -> throw IllegalArgumentException("$padding signature padding is not supported.")
    }
}

private fun Array<String>.toDigests() = firstOrNull()?.let { digest ->
    when (digest) {
        NativeKeyProperties.DIGEST_SHA256 -> Digest.SHA_256
        NativeKeyProperties.DIGEST_SHA384 -> Digest.SHA_384
        NativeKeyProperties.DIGEST_SHA512 -> Digest.SHA_512
        else -> throw IllegalArgumentException("$digest digest is not supported.")
    }
}

private fun Int.toKeyPurposes(): Set<KeyPurpose> {
    val result = mutableSetOf<KeyPurpose>()
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_DECRYPT)) result.add(KeyPurpose.Decryption)
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_ENCRYPT)) result.add(KeyPurpose.Encryption)
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_VERIFY)) result.add(KeyPurpose.SignatureVerification)
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_SIGN)) result.add(KeyPurpose.Signing)
    if (hasFlag(android.security.keystore.KeyProperties.PURPOSE_WRAP_KEY)) result.add(KeyPurpose.Wrapping)
    return result
}

private fun String.toKeyAlgorithm() = when (this) {
    android.security.keystore.KeyProperties.KEY_ALGORITHM_AES -> Algorithm.AES
    android.security.keystore.KeyProperties.KEY_ALGORITHM_RSA -> Algorithm.RSA
    else -> throw IllegalArgumentException("$this algorithm is not a supported.")
}

private fun Int.hasFlag(flag: Int) = (this and flag) == flag
