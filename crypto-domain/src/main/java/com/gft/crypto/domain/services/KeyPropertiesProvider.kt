package com.gft.crypto.domain.services

import com.gft.crypto.domain.model.KeyProperties
import com.gft.crypto.domain.model.KeyUsageScope

interface KeyPropertiesProvider<T : KeyUsageScope> {
    fun <R : T> getKeyProperties(usageScope: R): Set<KeyProperties>
}
