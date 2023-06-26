package com.gft.crypto.domain.services

import com.gft.crypto.domain.model.KeyProperties
import java.security.Key

interface KeyPropertiesResolver {
    fun resolveKeyProperties(key: Key): KeyProperties
}