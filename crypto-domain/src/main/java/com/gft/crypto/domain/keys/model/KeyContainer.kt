package com.gft.crypto.domain.keys.model

import com.gft.crypto.domain.common.model.Transformation
import java.security.Key

data class KeyContainer<SupportedTransformation : Transformation>(
    val key: Key,
    val properties: KeyProperties<SupportedTransformation>
)
