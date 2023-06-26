package com.gft.crypto.domain.services

import com.gft.crypto.domain.model.KeyContainer
import com.gft.crypto.domain.model.KeyUsageScope

interface KeysFactory<T : KeyUsageScope> {
    fun <R : T> generateKey(usageScope: R): Set<KeyContainer>
}
