package com.gft.crypto.domain.encryption.model

import java.io.Serializable

@Deprecated(
    message = "Use com.gft.crypto.encryption.model.IvParam instead.",
    replaceWith = ReplaceWith("com.gft.crypto.encryption.model.IvParam"),
    level = DeprecationLevel.WARNING
)
class IvParam (
    val iv: ByteArray
) : Serializable {
    companion object {
        private const val serialVersionUID : Long = 9162255791031369367
    }
}
