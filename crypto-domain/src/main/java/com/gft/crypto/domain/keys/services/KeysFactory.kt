package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.keys.model.KeyUsageScope

interface KeysFactory<T : KeyUsageScope> {
    fun <R : T> generateKey(usageScope: R): Set<KeyContainer>
}
