package com.gft.crypto.domain.common.model

@JvmInline
value class BlockMode private constructor(val name: String) {
    companion object {
        val ECB = BlockMode("ECB")
        val CBC = BlockMode("CBC")
        val CTR = BlockMode("CTR")
        val GCM = BlockMode("GCM")

        fun valueOf(name: String) = when (name) {
            ECB.name -> ECB
            CBC.name -> CBC
            CTR.name -> CTR
            GCM.name -> GCM
            else -> BlockMode(name)
        }
    }
}
