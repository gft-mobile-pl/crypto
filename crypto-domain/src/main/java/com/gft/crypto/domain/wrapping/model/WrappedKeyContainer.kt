package com.gft.crypto.domain.wrapping.model

import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.keys.model.KeyType
import java.util.Base64

private const val PARAMS_SEPARATOR = ":"

class WrappedKeyContainer(
    val wrappedKeyBytes: ByteArray,
    val wrappedKeyAlgorithm: Algorithm,
    val wrappedKeyType: KeyType,
    val wrappingAlgorithmParams: String?
) {
    override fun toString(): String {
        var result = Base64.getEncoder().encodeToString(wrappedKeyBytes) +
            PARAMS_SEPARATOR + wrappedKeyAlgorithm.name +
            PARAMS_SEPARATOR + wrappedKeyType.name
        if (wrappingAlgorithmParams != null) {
            result += PARAMS_SEPARATOR + wrappingAlgorithmParams
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
                wrappingAlgorithmParams = if (dataChunks.size == 4) dataChunks[3] else null
            )
        }
    }
}