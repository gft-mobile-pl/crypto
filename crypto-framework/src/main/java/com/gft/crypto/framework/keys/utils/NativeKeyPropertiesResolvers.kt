package com.gft.crypto.framework.keys.utils

import android.annotation.SuppressLint
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.Digest
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.common.model.SignaturePadding
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.keys.model.RandomizationPolicy
import com.gft.crypto.domain.keys.model.UnlockPolicy
import com.gft.crypto.domain.keys.model.UserAuthenticationPolicy
import kotlin.time.Duration
import kotlin.time.DurationUnit

internal fun BlockMode.toNativeBlockMode() = when (this.name) {
    BlockMode.ECB.name -> KeyProperties.BLOCK_MODE_ECB
    BlockMode.CBC.name -> KeyProperties.BLOCK_MODE_CBC
    BlockMode.CTR.name -> KeyProperties.BLOCK_MODE_CTR
    BlockMode.GCM.name -> KeyProperties.BLOCK_MODE_GCM
    else -> throw IllegalArgumentException("Provided block mode is not supported by Android Key Store.")
}

internal fun Digest.toNativeDigest() = when (this.name) {
    Digest.NONE.name -> KeyProperties.DIGEST_NONE
    Digest.MD5.name -> KeyProperties.DIGEST_MD5
    Digest.SHA_1.name -> KeyProperties.DIGEST_SHA1
    Digest.SHA_224.name -> KeyProperties.DIGEST_SHA224
    Digest.SHA_256.name -> KeyProperties.DIGEST_SHA256
    Digest.SHA_384.name -> KeyProperties.DIGEST_SHA384
    Digest.SHA_512.name -> KeyProperties.DIGEST_SHA512
    else -> throw IllegalArgumentException("Provided digest is not supported by Android Key Store.")
}

internal fun SignaturePadding.toNativePadding() = when (this.name) {
    SignaturePadding.NONE.name -> null
    SignaturePadding.PKCS1.name -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
    SignaturePadding.PSS.name -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
    else -> throw IllegalArgumentException("Provided signature padding is not supported by Android Key Store.")
}

internal fun EncryptionPadding.toNativePadding() = when (this.name) {
    EncryptionPadding.NONE.name -> KeyProperties.ENCRYPTION_PADDING_NONE
    EncryptionPadding.PKCS1.name -> KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
    EncryptionPadding.PKCS7.name -> KeyProperties.ENCRYPTION_PADDING_PKCS7
    EncryptionPadding.OAEP.name,
    EncryptionPadding.OAEP_SHA_1_MGF1.name,
    EncryptionPadding.OAEP_SHA_224_MGF1.name,
    EncryptionPadding.OAEP_SHA_256_MGF1.name,
    EncryptionPadding.OAEP_SHA_384_MGF1.name,
    EncryptionPadding.OAEP_SHA_512_MGF1.name -> KeyProperties.ENCRYPTION_PADDING_RSA_OAEP

    else -> throw IllegalArgumentException("Provided encryption padding is not supported by Android Key Store.")

}

internal fun UnlockPolicy.toUnlockRequired() = when (this) {
    UnlockPolicy.NotRequired -> false
    UnlockPolicy.Required -> true
    UnlockPolicy.Unknown -> throw IllegalArgumentException("UnlockPolicy.Unknown is not a valid unlock policy.")
}

internal fun Algorithm.toNativeKeyAlgorithm() = when (this.name) {
    Algorithm.AES.name -> KeyProperties.KEY_ALGORITHM_AES
    Algorithm.RSA.name -> KeyProperties.KEY_ALGORITHM_RSA
    Algorithm.ECDSA.name -> KeyProperties.KEY_ALGORITHM_EC
    Algorithm.HMAC_SHA_1.name -> KeyProperties.KEY_ALGORITHM_HMAC_SHA1
    Algorithm.HMAC_SHA_224.name -> KeyProperties.KEY_ALGORITHM_HMAC_SHA224
    Algorithm.HMAC_SHA_256.name -> KeyProperties.KEY_ALGORITHM_HMAC_SHA256
    Algorithm.HMAC_SHA_384.name -> KeyProperties.KEY_ALGORITHM_HMAC_SHA384
    Algorithm.HMAC_SHA_512.name -> KeyProperties.KEY_ALGORITHM_HMAC_SHA512
    else -> throw IllegalArgumentException("Provided algorithm is not supported by Android Key Store.")
}

internal fun Transformation.toNativeKeyPurpose() = when (this) {
    is Transformation.DataEncryption -> KeyProperties.PURPOSE_ENCRYPT + KeyProperties.PURPOSE_DECRYPT
    is Transformation.KeyWrapping -> KeyProperties.PURPOSE_WRAP_KEY + KeyProperties.PURPOSE_DECRYPT + KeyProperties.PURPOSE_ENCRYPT
    is Transformation.MessageSigning -> KeyProperties.PURPOSE_SIGN + KeyProperties.PURPOSE_VERIFY
}

@SuppressLint("WrongConstant")
internal fun com.gft.crypto.domain.keys.model.KeyProperties<*>.toKeyGenParameterSpec(alias: String) = KeyGenParameterSpec
    .Builder(
        alias,
        supportedTransformation.toNativeKeyPurpose()
    )
    .apply {
        setKeySize(keySize)
        when (val transformation = supportedTransformation) {
            is Transformation.MessageSigning -> {
                setDigests(transformation.digest.toNativeDigest())
                setSignaturePaddings(transformation.padding.toNativePadding())
            }

            is Transformation.DataEncryption -> {
                setBlockModes(transformation.blockMode.toNativeBlockMode())
                setDigests(transformation.digest.toNativeDigest())
                setEncryptionPaddings(transformation.padding.toNativePadding())
            }
            is Transformation.KeyWrapping -> {
                setBlockModes(transformation.blockMode.toNativeBlockMode())
                setDigests(transformation.digest.toNativeDigest())
                setEncryptionPaddings(transformation.padding.toNativePadding())
            }
        }
        when (val authenticationPolicy = userAuthenticationPolicy) {
            is UserAuthenticationPolicy.Required -> {
                if (authenticationPolicy.timeout <= Duration.ZERO) {
                    throw IllegalArgumentException("timeout value of UserAuthenticationPolicy.Required should be greater than 0.")
                }
                setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(
                        authenticationPolicy.timeout.toInt(DurationUnit.SECONDS),
                        KeyProperties.AUTH_DEVICE_CREDENTIAL + KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(
                        authenticationPolicy.timeout.toInt(DurationUnit.SECONDS),
                    )
                }
            }

            is UserAuthenticationPolicy.RequiredAfterBoot -> {
                setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(
                        Int.MAX_VALUE,
                        KeyProperties.AUTH_DEVICE_CREDENTIAL + KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(Int.MAX_VALUE)
                }
            }

            is UserAuthenticationPolicy.BiometricAuthenticationRequiredOnEachUse -> {
                setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(-1)
                }
            }

            UserAuthenticationPolicy.NotRequired -> {
                setUserAuthenticationRequired(false)
            }
        }
        setUnlockedDeviceRequired(unlockPolicy.toUnlockRequired())
        setRandomizedEncryptionRequired(randomizationPolicy == RandomizationPolicy.Required)
    }
    .build()
