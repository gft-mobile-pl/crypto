package com.gft.crypto.domain.keys.repositories

import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.keys.model.KeyUsageScope

interface KeysRepository<T : KeyUsageScope> {
    fun <R : T> createKey(alias: String, keyUsageScope: R)
    fun getKey(alias: String): Set<KeyContainer>
    fun deleteKey(alias: String)
}
