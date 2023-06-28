package com.gft.crypto.domain.common.model

data class CryptographicOperationParams(
    val algorithm: Algorithm,
    val digests: Digest?,
    val encryptionPaddings: EncryptionPadding?,
    val signaturePaddings: SignaturePadding?,
    val blockModes: BlockMode?
)
