package com.gft.crypto.domain.common.model

@JvmInline
value class EncryptionPadding(val name: String) {
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
    }
}

@JvmInline
value class SignaturePadding(val name: String) {
    companion object {
        val NONE = SignaturePadding("NONE")
        val PKCS1 = SignaturePadding("PKCS1")
        val PSS = SignaturePadding("PSS")
    }
}
