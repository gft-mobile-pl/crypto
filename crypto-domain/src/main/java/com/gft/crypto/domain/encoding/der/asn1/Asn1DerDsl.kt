package com.gft.crypto.domain.encoding.der.asn1

// Based on https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types
@DslMarker
annotation class Asn1DerDslMarker

// https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-der-transfer-syntax
sealed interface Asn1DerPrimitive

@Asn1DerDslMarker
class Asn1DerBuilder {
    val items = mutableListOf<Asn1DerPrimitive>()
    fun build() = Asn1Der(items.toList())
}
class Asn1Der(val items: List<Asn1DerPrimitive>) {
    fun encode() = Asn1DerEncoder().encode(items.toList())
}

@Asn1DerDslMarker
class SequenceBuilder {
    val items = mutableListOf<Asn1DerPrimitive>()
    fun build() = Sequence(items.toList())
}
class Sequence(val items: List<Asn1DerPrimitive>) : Asn1DerPrimitive

@Asn1DerDslMarker
class OctetString(
    val byteArray: ByteArray
) : Asn1DerPrimitive


fun asn1der(block: Asn1DerBuilder.() -> Unit) = Asn1DerBuilder().apply(block).build().encode()
fun Asn1DerBuilder.sequence(block: SequenceBuilder.() -> Unit) = SequenceBuilder().apply(block).build().also(items::add)
fun Asn1DerBuilder.octetString(byteArray: ByteArray) = OctetString(byteArray).also(items::add)
fun SequenceBuilder.octetString(byteArray: ByteArray) = OctetString(byteArray).also(items::add)
