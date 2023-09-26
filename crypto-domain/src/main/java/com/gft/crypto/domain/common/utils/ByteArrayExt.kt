package com.gft.crypto.domain.common.utils

import kotlin.experimental.xor

fun ByteArray.xor(panBlock: ByteArray) = ByteArray(this.size)
    .also { result ->
        for (index in this.indices) {
            result[index] = this[index] xor panBlock[index]
        }
    }
