package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.keys.model.KeyUsageScope

interface KeyPropertiesProvider<T : KeyUsageScope> {
    fun <R : T> getKeyProperties(usageScope: R): Set<KeyProperties>
}
