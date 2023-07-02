package com.gft.crypto.domain.keys.model

import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.Digest
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.common.model.SignaturePadding
import com.gft.crypto.domain.common.model.Transformation.DataEncryption
import com.gft.crypto.domain.common.model.Transformation.KeyWrapping
import com.gft.crypto.domain.common.model.Transformation.MessageSigning

sealed interface KeyStoreCompatibleMessageSigning : KeyStoreCompatible {
    object NONE_RSA : MessageSigning(Algorithm.RSA, Digest.NONE, SignaturePadding.PKCS1), KeyStoreCompatibleMessageSigning
    object MD5_RSA : MessageSigning(Algorithm.RSA, Digest.MD5, SignaturePadding.PKCS1), KeyStoreCompatibleMessageSigning
    object SHA1_RSA : MessageSigning(Algorithm.RSA, Digest.SHA_1, SignaturePadding.PKCS1), KeyStoreCompatibleMessageSigning
    object SHA224_RSA : MessageSigning(Algorithm.RSA, Digest.SHA_224, SignaturePadding.PKCS1), KeyStoreCompatibleMessageSigning
    object SHA256_RSA : MessageSigning(Algorithm.RSA, Digest.SHA_256, SignaturePadding.PKCS1), KeyStoreCompatibleMessageSigning
    object SHA384_RSA : MessageSigning(Algorithm.RSA, Digest.SHA_384, SignaturePadding.PKCS1), KeyStoreCompatibleMessageSigning
    object SHA512_RSA : MessageSigning(Algorithm.RSA, Digest.SHA_512, SignaturePadding.PKCS1), KeyStoreCompatibleMessageSigning
    object SHA1_RSA_PSS : MessageSigning(Algorithm.RSA, Digest.SHA_1, SignaturePadding.PSS), KeyStoreCompatibleMessageSigning
    object SHA224_RSA_PSS : MessageSigning(Algorithm.RSA, Digest.SHA_224, SignaturePadding.PSS), KeyStoreCompatibleMessageSigning
    object SHA256_RSA_PSS : MessageSigning(Algorithm.RSA, Digest.SHA_256, SignaturePadding.PSS), KeyStoreCompatibleMessageSigning
    object SHA384_RSA_PSS : MessageSigning(Algorithm.RSA, Digest.SHA_384, SignaturePadding.PSS), KeyStoreCompatibleMessageSigning
    object SHA512_RSA_PSS : MessageSigning(Algorithm.RSA, Digest.SHA_512, SignaturePadding.PSS), KeyStoreCompatibleMessageSigning
    object NONE_ECDSA : MessageSigning(Algorithm.ECDSA, Digest.NONE, SignaturePadding.NONE), KeyStoreCompatibleMessageSigning
    object SHA1_ECDSA : MessageSigning(Algorithm.ECDSA, Digest.SHA_1, SignaturePadding.NONE), KeyStoreCompatibleMessageSigning
    object SHA224_ECDSA : MessageSigning(Algorithm.ECDSA, Digest.SHA_224, SignaturePadding.NONE), KeyStoreCompatibleMessageSigning
    object SHA256_ECDSA : MessageSigning(Algorithm.ECDSA, Digest.SHA_256, SignaturePadding.NONE), KeyStoreCompatibleMessageSigning
    object SHA384_ECDSA : MessageSigning(Algorithm.ECDSA, Digest.SHA_384, SignaturePadding.NONE), KeyStoreCompatibleMessageSigning
    object SHA512_ECDSA : MessageSigning(Algorithm.ECDSA, Digest.SHA_512, SignaturePadding.NONE), KeyStoreCompatibleMessageSigning
}

sealed interface KeyStoreCompatibleDataEncryption : KeyStoreCompatible {
    object AES_ECB_NoPadding : DataEncryption(Algorithm.AES, BlockMode.ECB, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleDataEncryption
    object AES_ECB_PKCS7Padding : DataEncryption(Algorithm.AES, BlockMode.ECB, Digest.NONE, EncryptionPadding.PKCS7), KeyStoreCompatibleDataEncryption
    object AES_CBC_NoPadding : DataEncryption(Algorithm.AES, BlockMode.CBC, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleDataEncryption
    object AES_CBC_PKCS7Padding : DataEncryption(Algorithm.AES, BlockMode.CBC, Digest.NONE, EncryptionPadding.PKCS7), KeyStoreCompatibleDataEncryption
    object AES_CTR_NoPadding : DataEncryption(Algorithm.AES, BlockMode.CTR, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleDataEncryption
    object AES_GCM_NoPadding : DataEncryption(Algorithm.AES, BlockMode.GCM, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleDataEncryption
    object RSA_ECB_NoPadding : DataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleDataEncryption
    object RSA_ECB_PKCS1Padding : DataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.NONE, EncryptionPadding.PKCS1), KeyStoreCompatibleDataEncryption
    object RSA_ECB_OAEPPadding : DataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_1, EncryptionPadding.OAEP), KeyStoreCompatibleDataEncryption
    object RSA_ECB_OAEPWithSHA_1AndMGF1Padding : DataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_1, EncryptionPadding.OAEP_SHA_1_MGF1), KeyStoreCompatibleDataEncryption
    object RSA_ECB_OAEPWithSHA_224AndMGF1Padding : DataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_224, EncryptionPadding.OAEP_SHA_224_MGF1), KeyStoreCompatibleDataEncryption
    object RSA_ECB_OAEPWithSHA_256AndMGF1Padding : DataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_256, EncryptionPadding.OAEP_SHA_256_MGF1), KeyStoreCompatibleDataEncryption
    object RSA_ECB_OAEPWithSHA_384AndMGF1Padding : DataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_384, EncryptionPadding.OAEP_SHA_384_MGF1), KeyStoreCompatibleDataEncryption
    object RSA_ECB_OAEPWithSHA_512AndMGF1Padding : DataEncryption(Algorithm.RSA, BlockMode.ECB, Digest.SHA_512, EncryptionPadding.OAEP_SHA_512_MGF1), KeyStoreCompatibleDataEncryption
}

sealed interface KeyStoreCompatibleKeyWrapping : KeyStoreCompatible {
    object AES_ECB_NoPadding : KeyWrapping(Algorithm.AES, BlockMode.ECB, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleKeyWrapping
    object AES_ECB_PKCS7Padding : KeyWrapping(Algorithm.AES, BlockMode.ECB, Digest.NONE, EncryptionPadding.PKCS7), KeyStoreCompatibleKeyWrapping
    object AES_CBC_NoPadding : KeyWrapping(Algorithm.AES, BlockMode.CBC, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleKeyWrapping
    object AES_CBC_PKCS7Padding : KeyWrapping(Algorithm.AES, BlockMode.CBC, Digest.NONE, EncryptionPadding.PKCS7), KeyStoreCompatibleKeyWrapping
    object AES_CTR_NoPadding : KeyWrapping(Algorithm.AES, BlockMode.CTR, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleKeyWrapping
    object AES_GCM_NoPadding : KeyWrapping(Algorithm.AES, BlockMode.GCM, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleKeyWrapping
    object RSA_ECB_NoPadding : KeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.NONE, EncryptionPadding.NONE), KeyStoreCompatibleKeyWrapping
    object RSA_ECB_PKCS1Padding : KeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.NONE, EncryptionPadding.PKCS1), KeyStoreCompatibleKeyWrapping
    object RSA_ECB_OAEPPadding : KeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_1, EncryptionPadding.OAEP), KeyStoreCompatibleKeyWrapping
    object RSA_ECB_OAEPWithSHA_1AndMGF1Padding : KeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_1, EncryptionPadding.OAEP_SHA_1_MGF1), KeyStoreCompatibleKeyWrapping
    object RSA_ECB_OAEPWithSHA_224AndMGF1Padding : KeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_224, EncryptionPadding.OAEP_SHA_224_MGF1), KeyStoreCompatibleKeyWrapping
    object RSA_ECB_OAEPWithSHA_256AndMGF1Padding : KeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_256, EncryptionPadding.OAEP_SHA_256_MGF1), KeyStoreCompatibleKeyWrapping
    object RSA_ECB_OAEPWithSHA_384AndMGF1Padding : KeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_384, EncryptionPadding.OAEP_SHA_384_MGF1), KeyStoreCompatibleKeyWrapping
    object RSA_ECB_OAEPWithSHA_512AndMGF1Padding : KeyWrapping(Algorithm.RSA, BlockMode.ECB, Digest.SHA_512, EncryptionPadding.OAEP_SHA_512_MGF1), KeyStoreCompatibleKeyWrapping
}