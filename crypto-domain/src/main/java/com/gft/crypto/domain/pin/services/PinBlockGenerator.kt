package com.gft.crypto.domain.pin.services

import com.gft.crypto.domain.common.model.SecureText
import com.gft.crypto.domain.common.model.Transformation.DataEncryption
import com.gft.crypto.domain.common.utils.xor
import com.gft.crypto.domain.encryption.services.DataCipher
import javax.crypto.SecretKey

class PinBlockGenerator(
    private val dataCipher: DataCipher
) {

    fun generate(key: SecretKey, transformation: DataEncryption, pin: SecureText, pan: SecureText): ByteArray {
        val pinBlock = preparePinBlock(pin)
        val panBlock = preparePanBlock(pan)
        val intermediateBlockA = dataCipher.encrypt(key, transformation, pinBlock).perform().data
        val intermediateBlockB = intermediateBlockA.xor(panBlock)
        return dataCipher.encrypt(key, transformation, intermediateBlockB).perform().data
    }
}
