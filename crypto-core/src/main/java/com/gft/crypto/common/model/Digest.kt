package com.gft.crypto.common.model

@JvmInline
value class Digest private constructor(val name: String) {
    companion object {
        val NONE = Digest("NONE")
        val MD5 = Digest("MD5")
        val SHA_1 = Digest("SHA1")
        val SHA_224 = Digest("SHA224")
        val SHA_256 = Digest("SHA256")
        val SHA_384 = Digest("SHA384")
        val SHA_512 = Digest("SHA512")

        fun valueOf(name: String) = when (name) {
            NONE.name -> NONE
            MD5.name -> MD5
            SHA_1.name -> SHA_1
            SHA_224.name -> SHA_224
            SHA_256.name -> SHA_256
            SHA_384.name -> SHA_384
            SHA_512.name -> SHA_512
            else -> Digest(name)
        }
    }
}
