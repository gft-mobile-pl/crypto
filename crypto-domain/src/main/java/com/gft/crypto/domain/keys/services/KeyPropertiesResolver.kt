package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.keys.model.KeyProperties
import java.security.Key

interface KeyPropertiesResolver {
    fun resolveKeyProperties(key: Key): KeyProperties
}