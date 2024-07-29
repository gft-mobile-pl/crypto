package com.gft.crypto.wrapping.model

import com.gft.crypto.common.model.Algorithm
import com.gft.crypto.common.utils.deserialize
import com.gft.crypto.common.utils.serialize
import com.gft.crypto.keys.model.KeyType
import java.io.Serializable
import java.util.Base64

private const val PARAMS_SEPARATOR = ":"

class WrappedKeyContainer(
    val wrappedKeyBytes: ByteArray,
    val wrappedKeyAlgorithm: Algorithm,
    val wrappedKeyType: KeyType,
    val wrappingAlgorithmParams: Serializable?
) {
    override fun toString(): String {
        var result = Base64.getEncoder().encodeToString(wrappedKeyBytes) +
            PARAMS_SEPARATOR + wrappedKeyAlgorithm.name +
            PARAMS_SEPARATOR + wrappedKeyType.name
        if (wrappingAlgorithmParams != null) {
            result += PARAMS_SEPARATOR + wrappingAlgorithmParams.serialize()
        }
        return result
    }

    companion object {
        fun valueOf(data: String): WrappedKeyContainer {
            val dataChunks = data.split(PARAMS_SEPARATOR)
            return WrappedKeyContainer(
                wrappedKeyBytes = Base64.getDecoder().decode(dataChunks[0]),
                wrappedKeyAlgorithm = Algorithm.valueOf(dataChunks[1]),
                wrappedKeyType = KeyType.valueOf(dataChunks[2]),
                wrappingAlgorithmParams = if (dataChunks.size == 4) dataChunks[3].deserialize() else null
            )
        }
    }
}
