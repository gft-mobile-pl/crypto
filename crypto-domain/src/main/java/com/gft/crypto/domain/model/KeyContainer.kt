package com.gft.crypto.domain.model

import java.security.Key

class KeyContainer<T : KeyPurpose>(
    key: Key,
    keyPurpose: KeyPurpose
)