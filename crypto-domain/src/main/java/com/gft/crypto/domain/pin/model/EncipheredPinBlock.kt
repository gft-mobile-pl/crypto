package com.gft.crypto.domain.pin.model

import java.security.Key

class EncipheredPinBlock(
    val pinBlock: String,
    val encryptionKey: Key
)
