package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.common.model.UsageScope

interface KeysFactory<T : UsageScope> {
    fun <R : T> generateKey(usageScope: R): Set<KeyContainer>
}
