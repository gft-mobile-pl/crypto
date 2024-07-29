package com.gft.crypto.encryption.model

import com.gft.crypto.common.utils.deserialize
import com.gft.crypto.common.utils.serialize
import java.io.Serializable
import java.util.Base64

private const val PARAMS_SEPARATOR = ":"

class EncryptedData(
    val data: ByteArray,
    val algorithmParams: Serializable?
) {
    override fun toString(): String {
        var result = Base64.getEncoder().encodeToString(data)
        if (algorithmParams != null) {
            result += PARAMS_SEPARATOR + algorithmParams.serialize()
        }
        return result
    }

    companion object {
        fun valueOf(data: String): EncryptedData {
            val dataChunks = data.split(PARAMS_SEPARATOR)
            return EncryptedData(
                data = Base64.getDecoder().decode(dataChunks[0]),
                algorithmParams = if (dataChunks.size == 2) dataChunks[1].deserialize() else null
            )
        }
    }
}
