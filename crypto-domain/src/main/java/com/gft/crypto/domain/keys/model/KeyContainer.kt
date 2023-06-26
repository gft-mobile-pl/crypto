package com.gft.crypto.domain.keys.model

import java.security.Key

data class KeyContainer(
    val key: Key,
    val keyPurposes: Set<KeyPurpose>
)
