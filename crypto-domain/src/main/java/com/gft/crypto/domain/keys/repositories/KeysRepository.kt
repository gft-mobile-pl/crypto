package com.gft.crypto.domain.keys.repositories

import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.common.model.UsageScope

interface KeysRepository<T : UsageScope> {
    fun containsKey(alias: String): Boolean
    fun <R : T> createKey(alias: String, usageScope: R)
    fun getKey(alias: String): Set<KeyContainer>
    fun deleteKey(alias: String)
}
