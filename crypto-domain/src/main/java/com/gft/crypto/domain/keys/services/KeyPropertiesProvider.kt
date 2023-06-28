package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.common.model.UsageScope

interface KeyPropertiesProvider<T : UsageScope> {
    fun getKeyProperties(usageScope: T): KeyProperties
}
