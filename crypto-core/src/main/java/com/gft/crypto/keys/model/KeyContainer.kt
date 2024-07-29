package com.gft.crypto.keys.model

import com.gft.crypto.common.model.Transformation
import java.security.Key

data class KeyContainer<SupportedTransformation : Transformation>(
    val key: Key,
    val properties: KeyProperties<SupportedTransformation>
)
