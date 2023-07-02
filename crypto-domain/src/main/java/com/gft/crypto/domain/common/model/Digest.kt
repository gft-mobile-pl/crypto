package com.gft.crypto.domain.common.model

@JvmInline
value class Digest(val name: String) {
    companion object {
        val NONE = Digest("NONE")
        val MD5 = Digest("MD5")
        val SHA_1 = Digest("SHA1")
        val SHA_224 = Digest("SHA224")
        val SHA_256 = Digest("SHA256")
        val SHA_384 = Digest("SHA384")
        val SHA_512 = Digest("SHA512")
    }
}
