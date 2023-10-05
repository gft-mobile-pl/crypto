package com.gft.crypto.domain.encoding.der.asn1

import assertk.assertThat
import assertk.assertions.isEqualTo
import org.junit.jupiter.api.Test

class Asn1DerTest {

    @Test
    fun `sequence with two octet strings`() {
        // given
        val expectedResult = byteArrayOf(
            0x30, 2 + 32 + 2 + 16,
                0x04, 32,
                    185.toByte(), 44, 71, 243.toByte(), 49, 111, 1, 38, 51, 204.toByte(),
                    186.toByte(), 230.toByte(), 108, 130.toByte(), 196.toByte(), 9, 194.toByte(), 125, 236.toByte(), 45,
                    4, 70, 255.toByte(), 144.toByte(), 91, 45, 228.toByte(), 170.toByte(), 59, 163.toByte(),
                    211.toByte(), 96,
                0x04, 16,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        )
        // when
        val result = asn1der {
            sequence {
                octetString(byteArrayOf(
                    185.toByte(), 44, 71, 243.toByte(), 49, 111, 1, 38, 51, 204.toByte(), 186.toByte(), 230.toByte(), 108, 130.toByte(),
                    196.toByte(), 9, 194.toByte(), 125, 236.toByte(), 45, 4, 70, 255.toByte(), 144.toByte(), 91, 45, 228.toByte(),
                    170.toByte(), 59, 163.toByte(), 211.toByte(), 96
                ))
                octetString(ByteArray(size = 16))
            }
        }

        // then
        assertThat(result).isEqualTo(expectedResult)
    }

    @Test
    fun `single length byte size test, 1 byte sized value`() {
        // given
        val expectedResult = byteArrayOf(0x04, 0x01, 0x01)

        // when
        val result = asn1der {
            octetString(byteArrayOf(0x1))
        }

        // then
        assertThat(result).isEqualTo(expectedResult)
    }

    @Test
    fun `single length byte size test, max size value`() {
        // given
        val expectedResult = byteArrayOf(0x04, 0x7F.toByte(), *ByteArray(size = 127) { idx -> idx.toByte() })

        // when
        val result = asn1der {
            octetString(ByteArray(size = 127) { idx -> idx.toByte() })
        }

        // then
        assertThat(result).isEqualTo(expectedResult)
    }

    @Test
    fun `multiple length byte size test, 128 byte sized value`() {
        // given
        val expectedResult = byteArrayOf(0x04, 0x81.toByte(), 128.toByte(), *ByteArray(size = 128) { idx -> idx.toByte() })

        // when
        val result = asn1der {
            octetString(ByteArray(size = 128) { idx -> idx.toByte() })
        }

        // then
        assertThat(result).isEqualTo(expectedResult)
    }

    @Test
    fun `multiple length byte size test, two bytes byte length of size of value`() {
        // given
        val expectedResult = byteArrayOf(0x04, 0x82.toByte(), 255.toByte(), 255.toByte(), *ByteArray(size = 65535) { idx -> idx.toByte() })

        // when
        val result = asn1der {
            octetString(ByteArray(size = 65535) { idx -> idx.toByte() })
        }

        // then
        assertThat(result).isEqualTo(expectedResult)
    }
}
