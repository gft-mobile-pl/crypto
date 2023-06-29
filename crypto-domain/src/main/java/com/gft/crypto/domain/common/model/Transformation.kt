package com.gft.crypto.domain.common.model

sealed interface Transformation {
    val algorithm: Algorithm
}

class MessageSigning(
    override val algorithm: Algorithm,
    val digest: Digest,
    val padding: SignaturePadding
) : Transformation

sealed interface Encryption : Transformation {
    val blockModes: BlockMode
    val padding: EncryptionPadding
}

class DataEncryption(
    override val algorithm: Algorithm,
    override val blockModes: BlockMode,
    override val padding: EncryptionPadding
) : Encryption

class KeyWrapping(
    override val algorithm: Algorithm,
    override val blockModes: BlockMode,
    override val padding: EncryptionPadding
) : Encryption