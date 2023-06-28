package com.gft.crypto.domain.common.model

data class CryptographicProperties(
    val algorithm: Algorithm,
    val digests: Set<Digest>,
    val encryptionPaddings: Set<EncryptionPadding>,
    val signaturePaddings: Set<SignaturePadding>,
    val blockModes: Set<BlockMode>
)
