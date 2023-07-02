package com.gft.crypto.domain.keys.services

import com.gft.crypto.domain.keys.model.KeyProperties
import java.security.Key

interface KeyPropertiesExtractor {
    fun resolveKeyProperties(key: Key): KeyProperties<*>
}