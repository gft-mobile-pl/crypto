package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.common.model.CryptographicScope

interface KeyPropertiesProvider<T : CryptographicScope> {
    fun getKeyProperties(scope: T): KeyProperties
}
