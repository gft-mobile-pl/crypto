package com.gft.crypto.domain.common.model


@JvmInline
value class Algorithm(val name: String) {
    companion object {
        val AES = Algorithm("AES")
        val RSA = Algorithm("RSA")
        val ECDSA = Algorithm("ECDSA")
        val HMAC_SHA_1 = Algorithm("HmacSHA1")
        val HMAC_SHA_224 = Algorithm("HmacSHA224")
        val HMAC_SHA_256 = Algorithm("HmacSHA256")
        val HMAC_SHA_384 = Algorithm("HmacSHA384")
        val HMAC_SHA_512 = Algorithm("HmacSHA512")
    }
}
