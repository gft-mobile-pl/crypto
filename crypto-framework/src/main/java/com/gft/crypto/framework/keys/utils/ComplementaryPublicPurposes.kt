package com.gft.crypto.framework.keys.utils

import com.gft.crypto.domain.keys.model.KeyPurpose

fun Set<KeyPurpose>.resolveComplementaryPublicPurposes() = mapNotNull { keyPurpose ->
    when (keyPurpose) {
        KeyPurpose.Decryption -> KeyPurpose.Encryption
        KeyPurpose.Signing -> KeyPurpose.SignatureVerification
        KeyPurpose.Wrapping -> KeyPurpose.Wrapping
        else -> null
    }
}.toSet()