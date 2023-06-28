package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.common.model.CryptographicScope

interface KeysFactory<T : CryptographicScope> {
    fun <R : T> generateKey(scope: R): Set<KeyContainer>
}
