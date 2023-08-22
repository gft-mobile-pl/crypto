package com.gft.crypto.domain.keys.model

import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.Digest
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.common.model.SignaturePadding
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.common.model.Transformation.DataEncryption
import com.gft.crypto.domain.common.model.Transformation.KeyWrapping
import com.gft.crypto.domain.common.model.Transformation.MessageSigning

sealed class KeyStoreCompatibleMessageSigning(
    algorithm: Algorithm,
    digest: Digest,
    padding: SignaturePadding
) : MessageSigning(algorithm, digest, padding), KeyStoreCompatible {
    object NONE_RSA : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.NONE, SignaturePadding.PKCS1)
    object MD5_RSA : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.MD5, SignaturePadding.PKCS1)
    object SHA1_RSA : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_1, SignaturePadding.PKCS1)
    object SHA224_RSA : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_224, SignaturePadding.PKCS1)
    object SHA256_RSA : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_256, SignaturePadding.PKCS1)
    object SHA384_RSA : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_384, SignaturePadding.PKCS1)
    object SHA512_RSA : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_512, SignaturePadding.PKCS1)
    object SHA1_RSA_PSS : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_1, SignaturePadding.PSS)
    object SHA224_RSA_PSS : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_224, SignaturePadding.PSS)
    object SHA256_RSA_PSS : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_256, SignaturePadding.PSS)
    object SHA384_RSA_PSS : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_384, SignaturePadding.PSS)
    object SHA512_RSA_PSS : KeyStoreCompatibleMessageSigning(Algorithm.RSA, Digest.SHA_512, SignaturePadding.PSS)
    object NONE_ECDSA : KeyStoreCompatibleMessageSigning(Algorithm.ECDSA, Digest.NONE, SignaturePadding.NONE)
    object SHA1_ECDSA : KeyStoreCompatibleMessageSigning(Algorithm.ECDSA, Digest.SHA_1, SignaturePadding.NONE)
    object SHA224_ECDSA : KeyStoreCompatibleMessageSigning(Algorithm.ECDSA, Digest.SHA_224, SignaturePadding.NONE)
    object SHA256_ECDSA : KeyStoreCompatibleMessageSigning(Algorithm.ECDSA, Digest.SHA_256, SignaturePadding.NONE)
    object SHA384_ECDSA : KeyStoreCompatibleMessageSigning(Algorithm.ECDSA, Digest.SHA_384, SignaturePadding.NONE)
    object SHA512_ECDSA : KeyStoreCompatibleMessageSigning(Algorithm.ECDSA, Digest.SHA_512, SignaturePadding.NONE)
    
    companion object {
        fun getAll() = setOf(
            NONE_RSA, MD5_RSA, SHA1_RSA, SHA224_RSA, SHA256_RSA, SHA384_RSA, SHA512_RSA,
            SHA1_RSA_PSS, SHA224_RSA_PSS, SHA256_RSA_PSS, SHA384_RSA_PSS, SHA512_RSA_PSS,
            NONE_ECDSA, SHA1_ECDSA, SHA224_ECDSA, SHA256_ECDSA, SHA384_ECDSA, SHA512_ECDSA
        )
    }
}

sealed class KeyStoreCompatibleDataEncryption(
    algorithm: Algorithm,
    blockMode: BlockMode,
    digest: Digest,
    padding: EncryptionPadding
) : DataEncryption(algorithm, blockMode, digest, padding), KeyStoreCompatible {
    object AES_ECB_NoPadding : KeyStoreCompatibleDataEncryption(Algorithm.AES, BlockMode.ECB, Digest.NONE, EncryptionPadding.NONE)
    object AES_ECB_PKCS7Padding : KeyStoreCompatibleDataEncryption(Algorithm.AES, BlockMode.ECB, Digest.NONE, EncryptionPadding.PKCS7)
    object AES_CBC_NoPadding : KeyStoreCompatibleDataEncryption(Algorithm.AES, BlockMode.CBC, Digest.NONE, EncryptionPadding.NONE)
    object AES_CBC_PKCS7Padding : KeyStoreCompatibleDataEncryption(Algorithm.AES, BlockMode.CBC, Digest.NONE, EncryptionPadding.PKCS7)
    object AES_CTR_NoPadding : KeyStoreCompatibleDataEncryption(Algorithm.AES, BlockMode.CTR, Digest.NONE, EncryptionPadding.NONE)
    object AES_GCM_NoPadding : KeyStoreCompatibleDataEncryption(Algorithm.AES, BlockMode.GCM, Digest.NONE, EncryptionPadding.NONE)
    object RSA_ECB_PKCS1Padding : KeyStoreCompatibleDataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.NONE, EncryptionPadding.PKCS1)
    object RSA_ECB_OAEPPadding : KeyStoreCompatibleDataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_1, EncryptionPadding.OAEP)
    object RSA_ECB_OAEPWithSHA_1AndMGF1Padding : KeyStoreCompatibleDataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_1, EncryptionPadding.OAEP_SHA_1_MGF1)
    object RSA_ECB_OAEPWithSHA_224AndMGF1Padding : KeyStoreCompatibleDataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_224, EncryptionPadding.OAEP_SHA_224_MGF1)
    object RSA_ECB_OAEPWithSHA_256AndMGF1Padding : KeyStoreCompatibleDataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_256, EncryptionPadding.OAEP_SHA_256_MGF1)
    object RSA_ECB_OAEPWithSHA_384AndMGF1Padding : KeyStoreCompatibleDataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_384, EncryptionPadding.OAEP_SHA_384_MGF1)
    object RSA_ECB_OAEPWithSHA_512AndMGF1Padding : KeyStoreCompatibleDataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_512, EncryptionPadding.OAEP_SHA_512_MGF1)
    
    companion object {
        fun getAll() = setOf(
            AES_ECB_NoPadding, AES_ECB_PKCS7Padding,
            AES_CBC_NoPadding, AES_CBC_PKCS7Padding, AES_CTR_NoPadding, AES_GCM_NoPadding,
            RSA_ECB_PKCS1Padding, RSA_ECB_OAEPPadding, RSA_ECB_OAEPWithSHA_1AndMGF1Padding, RSA_ECB_OAEPWithSHA_224AndMGF1Padding,
            RSA_ECB_OAEPWithSHA_256AndMGF1Padding, RSA_ECB_OAEPWithSHA_384AndMGF1Padding, RSA_ECB_OAEPWithSHA_512AndMGF1Padding
        )
    }
}

sealed class KeyStoreCompatibleKeyWrapping(
    algorithm: Algorithm,
    blockMode: BlockMode,
    digest: Digest,
    padding: EncryptionPadding
) : KeyWrapping(algorithm, blockMode, digest, padding), KeyStoreCompatible {
    object AES_ECB_NoPadding : KeyStoreCompatibleKeyWrapping(Algorithm.AES, BlockMode.ECB, Digest.NONE, EncryptionPadding.NONE)
    object AES_ECB_PKCS7Padding : KeyStoreCompatibleKeyWrapping(Algorithm.AES, BlockMode.ECB, Digest.NONE, EncryptionPadding.PKCS7)
    object AES_CBC_NoPadding : KeyStoreCompatibleKeyWrapping(Algorithm.AES, BlockMode.CBC, Digest.NONE, EncryptionPadding.NONE)
    object AES_CBC_PKCS7Padding : KeyStoreCompatibleKeyWrapping(Algorithm.AES, BlockMode.CBC, Digest.NONE, EncryptionPadding.PKCS7)
    object AES_CTR_NoPadding : KeyStoreCompatibleKeyWrapping(Algorithm.AES, BlockMode.CTR, Digest.NONE, EncryptionPadding.NONE)
    object AES_GCM_NoPadding : KeyStoreCompatibleKeyWrapping(Algorithm.AES, BlockMode.GCM, Digest.NONE, EncryptionPadding.NONE)
    object RSA_ECB_NoPadding : KeyStoreCompatibleKeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.NONE, EncryptionPadding.NONE)
    object RSA_ECB_PKCS1Padding : KeyStoreCompatibleKeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.NONE, EncryptionPadding.PKCS1)
    object RSA_ECB_OAEPPadding : KeyStoreCompatibleKeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_1, EncryptionPadding.OAEP)
    object RSA_ECB_OAEPWithSHA_1AndMGF1Padding : KeyStoreCompatibleKeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_1, EncryptionPadding.OAEP_SHA_1_MGF1)
    object RSA_ECB_OAEPWithSHA_224AndMGF1Padding : KeyStoreCompatibleKeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_224, EncryptionPadding.OAEP_SHA_224_MGF1)
    object RSA_ECB_OAEPWithSHA_256AndMGF1Padding : KeyStoreCompatibleKeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_256, EncryptionPadding.OAEP_SHA_256_MGF1)
    object RSA_ECB_OAEPWithSHA_384AndMGF1Padding : KeyStoreCompatibleKeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_384, EncryptionPadding.OAEP_SHA_384_MGF1)
    object RSA_ECB_OAEPWithSHA_512AndMGF1Padding : KeyStoreCompatibleKeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_512, EncryptionPadding.OAEP_SHA_512_MGF1)

    companion object {
        fun getAll() = setOf(
            AES_ECB_NoPadding, AES_ECB_PKCS7Padding,
            AES_CBC_NoPadding, AES_CBC_PKCS7Padding, AES_CTR_NoPadding, AES_GCM_NoPadding,
            RSA_ECB_NoPadding,
            RSA_ECB_PKCS1Padding, RSA_ECB_OAEPPadding, RSA_ECB_OAEPWithSHA_1AndMGF1Padding, RSA_ECB_OAEPWithSHA_224AndMGF1Padding,
            RSA_ECB_OAEPWithSHA_256AndMGF1Padding, RSA_ECB_OAEPWithSHA_384AndMGF1Padding, RSA_ECB_OAEPWithSHA_512AndMGF1Padding
        )
    }
}
