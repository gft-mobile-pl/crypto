package com.gft.crypto.domain.keys.model

import java.security.Key

class KeyContainer(
    key: Key,
    keyPurposes: Set<KeyPurpose>
)
