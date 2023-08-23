package com.gft.crypto.domain.common.utils

import kotlin.experimental.xor

fun ByteArray.xor(panBlock: ByteArray) = ByteArray(this.size)
    .apply {
        for (index in this.indices) {
            this[index] = this[index] xor panBlock[index]
        }
    }
