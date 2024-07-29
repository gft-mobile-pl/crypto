package com.gft.crypto.common.model

@JvmInline
value class Algorithm private constructor(val name: String) {
    companion object {
        val AES = Algorithm("AES")
        val RSA = Algorithm("RSA")
        val ECDSA = Algorithm("ECDSA")
        val HMAC_SHA_1 = Algorithm("HmacSHA1")
        val HMAC_SHA_224 = Algorithm("HmacSHA224")
        val HMAC_SHA_256 = Algorithm("HmacSHA256")
        val HMAC_SHA_384 = Algorithm("HmacSHA384")
        val HMAC_SHA_512 = Algorithm("HmacSHA512")

        fun valueOf(name: String) = when (name) {
            AES.name -> AES
            RSA.name -> RSA
            ECDSA.name -> ECDSA
            HMAC_SHA_1.name -> HMAC_SHA_1
            HMAC_SHA_224.name -> HMAC_SHA_224
            HMAC_SHA_256.name -> HMAC_SHA_256
            HMAC_SHA_384.name -> HMAC_SHA_384
            HMAC_SHA_512.name -> HMAC_SHA_512
            else -> Algorithm(name)
        }
    }
}
