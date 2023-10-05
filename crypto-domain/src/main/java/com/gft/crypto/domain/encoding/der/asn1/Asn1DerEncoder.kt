package com.gft.crypto.domain.encoding.der.asn1

import java.io.ByteArrayOutputStream
import java.lang.Math.abs

class Asn1DerEncoder {

    fun encode(items: List<Asn1DerPrimitive>): ByteArray = items.toValue()

    private fun List<Asn1DerPrimitive>.toValue() = ByteArrayOutputStream()
        .apply {
            forEach { item ->
                write(item.encode())
            }
        }
        .toByteArray()

    private fun Asn1DerPrimitive.encode(): ByteArray {
        val (tag, value) = when(this) {
            is Sequence    -> 0x30 to items.toValue()
            is OctetString -> 0x04 to byteArray
        }

        val length = value.length()

        return ByteArrayOutputStream()
            .apply {
                write(tag)
                write(length)
                write(value)
            }
            .toByteArray()
    }

    // https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-length-and-value-bytes
    private fun ByteArray.length() = when {
        size < SINGLE_LENGTH_BYTE_VALUE_SIZE_LIMIT -> {
            byteArrayOf(size.toByte())
        }
        else -> {
            val sizeAsBytes = size.toByteArray()
            byteArrayOf(
                (SINGLE_LENGTH_BYTE_VALUE_SIZE_LIMIT or sizeAsBytes.size).toByte(),
                *sizeAsBytes
            )
        }
    }

    private fun Int.toByteArray(): ByteArray {
        val a = (this ushr 24).toByte()
        val b = (this ushr 16).toByte()
        val c = (this ushr 8).toByte()
        val d = (this ushr 0).toByte()

        return when {
            a != 0.toByte() -> byteArrayOf(a, b, c, d)
            b != 0.toByte() -> byteArrayOf(b, c, d)
            c != 0.toByte() -> byteArrayOf(c, d)
            else -> byteArrayOf(d)
        }
    }
}

private val SINGLE_LENGTH_BYTE_VALUE_SIZE_LIMIT = 0x80 // 128, 1000 0000
