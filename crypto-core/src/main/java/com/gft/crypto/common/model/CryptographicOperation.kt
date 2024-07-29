package com.gft.crypto.common.model

interface CryptographicOperation<Processor, Output> {
    val processor: Processor
    fun perform(): Output
}
