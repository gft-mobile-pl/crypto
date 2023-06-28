package com.gft.crypto.domain.keys.repositories

import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.common.model.CryptographicScope

interface KeysRepository<T : CryptographicScope> {
    fun containsKey(alias: String): Boolean
    fun <R : T> createKey(alias: String, scope: R)
    fun getKey(alias: String): Set<KeyContainer>
    fun deleteKey(alias: String)
}
