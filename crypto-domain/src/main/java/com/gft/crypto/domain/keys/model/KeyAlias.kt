package com.gft.crypto.domain.keys.model

import com.gft.crypto.domain.common.model.Transformation

class KeyAlias<SupportedTransformation : Transformation>(val alias: String)
