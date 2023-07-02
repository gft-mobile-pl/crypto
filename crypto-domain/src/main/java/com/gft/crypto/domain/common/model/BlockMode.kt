package com.gft.crypto.domain.common.model

@JvmInline
value class BlockMode(val name: String) {
    companion object {
        val ECB = BlockMode("ECB")
        val CBC = BlockMode("CBC")
        val CTR = BlockMode("CTR")
        val GCM = BlockMode("GCM")
    }
}
