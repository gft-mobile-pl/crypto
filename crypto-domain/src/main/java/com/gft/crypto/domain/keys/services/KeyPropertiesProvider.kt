package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.keys.model.KeyUsageScope

interface KeyPropertiesProvider<T : KeyUsageScope> {
    fun getKeyProperties(usageScope: T): KeyProperties
}
