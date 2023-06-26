package com.gft.crypto.domain.keys.model

import kotlin.time.Duration

data class KeyProperties(
    val purposes: Set<KeyPurpose>,
    val algorithm: KeyAlgorithm,
    val keySize: Int,
    val unlockPolicy: UnlockPolicy,
    val userAuthenticationPolicy: UserAuthenticationPolicy,
    val digests: Set<Digest>,
    val encryptionPaddings: Set<EncryptionPadding>,
    val signaturePaddings: Set<SignaturePadding>,
    val blockModes: Set<BlockMode>
)

sealed interface UserAuthenticationPolicy {
    object NotRequired : UserAuthenticationPolicy
    object RequiredAfterBoot : UserAuthenticationPolicy
    object BiometricAuthenticationRequiredOnEachUse : UserAuthenticationPolicy
    data class Required(val timeout: Duration) : UserAuthenticationPolicy
}

sealed interface UnlockPolicy {
    object Required : UnlockPolicy
    object NotRequired : UnlockPolicy
    object Unknown : UnlockPolicy
}

enum class Digest {
    SHA_256,
    SHA_384,
    SHA_512
}

enum class EncryptionPadding {
    NONE,
    PKCS7,
    RSA_PKCS1,
    RSA_OAEP
}

enum class SignaturePadding {
    RSA_PKCS1,
    RSA_PSS,
}

enum class KeyAlgorithm {
    AES,
    RSA
}

enum class BlockMode {
    ECB,
    CBC,
    CTR,
    GCM
}
