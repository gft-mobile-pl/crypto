package com.gft.crypto.pin.services

import com.gft.crypto.common.model.SecureText
import com.gft.crypto.common.model.Transformation
import com.gft.crypto.common.utils.xor
import com.gft.crypto.encryption.model.EncryptedData
import com.gft.crypto.encryption.services.DataCipher
import javax.crypto.SecretKey

class PinBlockDecoder(
    private val dataCipher: DataCipher
) {

    fun decode(key: SecretKey, transformation: Transformation.DataEncryption, encryptedPinBlock: ByteArray, pan: SecureText): SecureText {
        val intermediateBlockB = dataCipher.decrypt(key, transformation, EncryptedData(encryptedPinBlock, null)).perform()
        val panBlock = preparePanBlock(pan)
        val intermediateBlockA = intermediateBlockB.xor(panBlock)
        val pinBlock = dataCipher.decrypt(key, transformation, EncryptedData(intermediateBlockA, null)).perform()
        val pin = decodePin(pinBlock)
        return SecureText(pin.joinToString("") { byte ->  byte.toString() }.toCharArray(), "pin")
    }
}
