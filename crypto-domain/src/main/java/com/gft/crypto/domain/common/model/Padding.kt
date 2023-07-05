package com.gft.crypto.domain.common.model

@JvmInline
value class EncryptionPadding private constructor(val name: String) {
    companion object {
        val NONE = EncryptionPadding("NoPadding")
        val PKCS1 = EncryptionPadding("PKCS1Padding")
        val PKCS7 = EncryptionPadding("PKCS7Padding")
        val OAEP = EncryptionPadding("OAEPPadding")
        val OAEP_SHA_1_MGF1 = EncryptionPadding("OAEPWithSHA-1AndMGF1Padding")
        val OAEP_SHA_224_MGF1 = EncryptionPadding("OAEPWithSHA-224AndMGF1Padding")
        val OAEP_SHA_256_MGF1 = EncryptionPadding("OAEPWithSHA-256AndMGF1Padding")
        val OAEP_SHA_384_MGF1 = EncryptionPadding("OAEPWithSHA-384AndMGF1Padding")
        val OAEP_SHA_512_MGF1 = EncryptionPadding("OAEPWithSHA-512AndMGF1Padding")

        fun valueOf(name: String) = when(name) {
            NONE.name -> NONE
            PKCS1.name -> PKCS1
            PKCS7.name -> PKCS7
            OAEP.name -> OAEP
            OAEP_SHA_1_MGF1.name -> OAEP_SHA_1_MGF1
            OAEP_SHA_224_MGF1.name -> OAEP_SHA_224_MGF1
            OAEP_SHA_256_MGF1.name -> OAEP_SHA_256_MGF1
            OAEP_SHA_384_MGF1.name -> OAEP_SHA_384_MGF1
            OAEP_SHA_512_MGF1.name -> OAEP_SHA_512_MGF1
            else -> EncryptionPadding(name)
        }
    }
}

@JvmInline
value class SignaturePadding private constructor(val name: String) {
    companion object {
        val NONE = SignaturePadding("NONE")
        val PKCS1 = SignaturePadding("PKCS1")
        val PSS = SignaturePadding("PSS")

        fun valueOf(name: String) = when(name) {
            NONE.name -> NONE
            PKCS1.name -> PKCS1
            PSS.name -> PSS
            else -> SignaturePadding(name)
        }
    }
}
