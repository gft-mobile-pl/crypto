package com.gft.crypto.encryption.model

import java.io.Serializable

class IvParam (
    val iv: ByteArray
) : Serializable {
    companion object {
        private const val serialVersionUID : Long = 9162255791031369367
    }
}
