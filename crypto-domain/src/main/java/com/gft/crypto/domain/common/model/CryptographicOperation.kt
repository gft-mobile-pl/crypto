package com.gft.crypto.domain.common.model

interface CryptographicOperation<Processor, Output> {
    val processor: Processor
    fun perform(): Output
}