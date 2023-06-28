package com.gft.crypto.framework.keys.utils

import android.security.keystore.KeyProperties
import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.Digest
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.keys.model.KeyPurpose
import com.gft.crypto.domain.common.model.SignaturePadding
import com.gft.crypto.domain.keys.model.UnlockPolicy

internal fun BlockMode.toNativeBlockMode() = when (this) {
    BlockMode.ECB -> KeyProperties.BLOCK_MODE_ECB
    BlockMode.CBC -> KeyProperties.BLOCK_MODE_CBC
    BlockMode.CTR -> KeyProperties.BLOCK_MODE_CTR
    BlockMode.GCM -> KeyProperties.BLOCK_MODE_GCM
}

internal fun KeyPurpose.toNativeKeyPurpose(): Int = when (this) {
    KeyPurpose.Decryption -> KeyProperties.PURPOSE_DECRYPT
    KeyPurpose.Encryption -> KeyProperties.PURPOSE_ENCRYPT
    KeyPurpose.SignatureVerification -> KeyProperties.PURPOSE_VERIFY
    KeyPurpose.Signing -> KeyProperties.PURPOSE_SIGN
    KeyPurpose.Wrapping -> KeyProperties.PURPOSE_WRAP_KEY
}

internal fun Digest.toNativeDigest() = when (this) {
    Digest.SHA_256 -> KeyProperties.DIGEST_SHA256
    Digest.SHA_384 -> KeyProperties.DIGEST_SHA384
    Digest.SHA_512 -> KeyProperties.DIGEST_SHA512
}

internal fun SignaturePadding.toNativePadding() = when (this) {
    SignaturePadding.RSA_PKCS1 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
    SignaturePadding.RSA_PSS -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
}

internal fun EncryptionPadding.toNativePadding() = when (this) {
    EncryptionPadding.NONE -> KeyProperties.ENCRYPTION_PADDING_NONE
    EncryptionPadding.PKCS7 -> KeyProperties.ENCRYPTION_PADDING_PKCS7
    EncryptionPadding.RSA_PKCS1 -> KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
    EncryptionPadding.RSA_OAEP -> KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
}

internal fun UnlockPolicy.toUnlockRequired() = when (this) {
    UnlockPolicy.NotRequired -> false
    UnlockPolicy.Required -> true
    UnlockPolicy.Unknown -> throw IllegalArgumentException("UnlockPolicy.Unknown is not a valid unlock policy.")
}

internal fun Algorithm.toNativeKeyAlgorithm() = when (this) {
    Algorithm.AES -> KeyProperties.KEY_ALGORITHM_AES
    Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA
}