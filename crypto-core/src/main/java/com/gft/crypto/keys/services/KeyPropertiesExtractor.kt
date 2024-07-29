package com.gft.crypto.keys.services

import com.gft.crypto.keys.model.KeyProperties
import java.security.Key

interface KeyPropertiesExtractor {
    fun resolveKeyProperties(key: Key): KeyProperties<*>
}
