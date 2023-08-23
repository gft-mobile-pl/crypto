package com.gft.crypto.domain.pin.services

import com.gft.crypto.domain.common.model.SecureText
import com.gft.crypto.domain.common.model.Transformation.DataEncryption
import com.gft.crypto.domain.common.utils.xor
import com.gft.crypto.domain.encryption.services.DataCipher
import com.gft.crypto.domain.pin.model.EncipheredPinBlock
import java.security.SecureRandom
import javax.crypto.SecretKey

private const val PIN_BLOCK_ISO_VERSION_NUMBER = 0x4
private const val PIN_BLOCK_PADDING_A = 0xA
private const val PIN_BLOCK_START_RANDOM_VALUES_INDEX = 16
private const val PAN_BLOCK_STANDARD_SIZE = 12
private const val PAN_BLOCK_STANDARD_SIZE_VALUE = 0x0
private const val PAN_BLOCK_PADDING_0 = 0x0
private const val BLOCK_SIZE = 32

class PinBlockGenerator(
    private val dataCipher: DataCipher
) {

    fun generate(key: SecretKey, transformation: DataEncryption, pin: SecureText, pan: SecureText): EncipheredPinBlock {
        val pinBlock = preparePinBlock(pin)
        val panBlock = preparePanBlock(pan)
        val intermediateBlockA = dataCipher.encrypt(key, transformation, pinBlock).perform().data
        val intermediateBlockB = intermediateBlockA.xor(panBlock)
        val encryptionResult = dataCipher.encrypt(key, transformation, intermediateBlockB).perform()
        return EncipheredPinBlock(encryptionResult.toString(), key)
    }

    private fun preparePinBlock(pin: SecureText): ByteArray = ByteArray(BLOCK_SIZE)
        .apply {
            var index = 0
            this[index] = PIN_BLOCK_ISO_VERSION_NUMBER.toByte()
            index++
            this[index] = pin.size.toByte()
            index++
            pin.text.forEach { digit ->
                this[index] = digit.digitToInt().toByte()
                index++
            }
            while (index < PIN_BLOCK_START_RANDOM_VALUES_INDEX) {
                this[index] = PIN_BLOCK_PADDING_A.toByte()
                index++
            }
            val random = SecureRandom.getInstanceStrong()
            val randomValues = ByteArray(BLOCK_SIZE - index)
            random.nextBytes(randomValues)
            randomValues.forEach { byte ->
                this[index] = byte
                index++
            }
        }

    private fun preparePanBlock(pan: SecureText): ByteArray = ByteArray(BLOCK_SIZE)
        .apply {
            var index = 0
            this[0] = when {
                pan.size < PAN_BLOCK_STANDARD_SIZE -> PAN_BLOCK_STANDARD_SIZE_VALUE
                else -> pan.size - PAN_BLOCK_STANDARD_SIZE
            }.toByte()
            index++
            while (index <= PAN_BLOCK_STANDARD_SIZE - pan.size) {
                this[index] = PAN_BLOCK_PADDING_0.toByte()
                index++
            }
            pan.text.forEach { digit ->
                this[index] = digit.digitToInt().toByte()
                index++
            }
            while (index < BLOCK_SIZE) {
                this[index] = PAN_BLOCK_PADDING_0.toByte()
                index++
            }
        }
}
