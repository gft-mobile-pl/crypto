package com.gft.crypto.domain.pin.services

import com.gft.crypto.domain.common.model.SecureText
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import kotlin.math.max

private const val PIN_BLOCK_ISO_VERSION_NUMBER = 0x4
private const val PIN_BLOCK_PADDING_A: Byte = 0xA
private const val PIN_BLOCK_START_RANDOM_VALUES_INDEX = 16
private const val PAN_BLOCK_STANDARD_SIZE = 12
private const val PAN_BLOCK_STANDARD_SIZE_ZERO_VALUE = 0x0
private const val PAN_BLOCK_PADDING_0: Byte = 0x0
private const val BLOCK_SIZE = 32
private const val PIN_LENGTH_VALUE_INDEX = 1
private const val PIN_VALUE_START_INDEX = 2

internal fun preparePinBlock(pin: SecureText) =
    ByteArrayOutputStream(BLOCK_SIZE)
        .apply {
            // 0. ISO4 Version Number
            write(PIN_BLOCK_ISO_VERSION_NUMBER)
            // 1. PIN Size
            write(pin.size)
            // 2-N, N < 14. PIN
            pin.text.forEach { digit ->
                write(digit.digitToInt())
            }
            // N-16. PIN padding (0xA)
            write(ByteArray(PIN_BLOCK_START_RANDOM_VALUES_INDEX - size()) { PIN_BLOCK_PADDING_A })
            // 16-32. Random bytes
            write(generateRandomHexDigits(size = BLOCK_SIZE - size()))
        }
        .toByteArray() // 32 hex digits, 0xF
        .fromHexArrayToByteArray() // 16 hex numbers, 0xFF

internal fun preparePanBlock(pan: SecureText) =
    ByteArrayOutputStream(BLOCK_SIZE)
        .apply {
            // 0. PAN size. max(0, size - 12)
            write(max(pan.size - PAN_BLOCK_STANDARD_SIZE, PAN_BLOCK_STANDARD_SIZE_ZERO_VALUE))
            // 1-M. Leading PAN padding, if size < 12, 0x0
            write(ByteArray(max(PAN_BLOCK_STANDARD_SIZE - pan.size, 0)) { PAN_BLOCK_PADDING_0 })
            // M(usually 2)-N(usually 14). PAN token
            pan.text.forEach { digit ->
                write(digit.digitToInt())
            }
            // N-32. Trailing PAN padding, 0x0
            write(ByteArray(BLOCK_SIZE - size()) { PAN_BLOCK_PADDING_0 })
        }
        .toByteArray() // 32 hex digits, 0xF
        .fromHexArrayToByteArray() // 16 hex numbers, 0xFF

internal fun decodePin(pinBlock: ByteArray): ByteArray {
    val pinBlockData = pinBlock.fromByteArrayToHexArray() // 32 hex digits, 0xF
    val pinLength = pinBlockData[PIN_LENGTH_VALUE_INDEX]
    return pinBlockData.copyOfRange(PIN_VALUE_START_INDEX, PIN_VALUE_START_INDEX + pinLength.toInt()) // pinLength digits, from index 2
}

private fun generateRandomHexDigits(size: Int): ByteArray {
    val random = SecureRandom.getInstanceStrong()
    return ByteArray(size) { random.nextInt(0xF).toByte() }
}

private fun ByteArray.fromHexArrayToByteArray(): ByteArray {
    val result = ByteArray(size / 2)

    for ((destIndex, srcIndex) in (indices step 2).withIndex()) {
        val lhs = this[srcIndex].toUInt().shl(4) // 0xF => 0xF0
        val rhs = this[srcIndex + 1].toUInt() // 0xF => 0x0F

        result[destIndex] = (lhs or rhs).toByte() // 0xFF
        this[srcIndex] = 0
        this[srcIndex + 1] = 0
    }

    return result
}

private fun ByteArray.fromByteArrayToHexArray(): ByteArray {
    val result = ByteArray(size * 2)

    for (index in indices) {
        result[index * 2] = (this[index].toUInt() shr 4).toByte() // 0xFF => 0xF0
        result[index * 2 + 1] = (this[index].toUInt() and 0x0F.toUInt()).toByte() // 0xFF => 0x0F
    }

    return result
}
