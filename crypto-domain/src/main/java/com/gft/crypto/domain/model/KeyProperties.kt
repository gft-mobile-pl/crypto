package com.gft.crypto.domain.model

import kotlin.time.Duration

data class KeyProperties(
    val purposes: Set<KeyPurpose>,
    val algorithm: KeyAlgorithm,
    val unlockRequired: Boolean,
    val userAuthenticationPolicy: UserAuthenticationPolicy,
    val digests: Set<Digests>,
    val encryptionPaddings: Set<EncryptionPadding>,
    val signaturePaddings: Set<SignaturePadding>,
    val blockModes: Set<BlockMode>
)

sealed interface UserAuthenticationPolicy {
    object NotRequired : UserAuthenticationPolicy
    data class RequiredAfterBoot(val authenticationStrength: UserAuthenticationStrength) : UserAuthenticationPolicy
    data class RequiredOnEachUse(val authenticationStrength: UserAuthenticationStrength) : UserAuthenticationPolicy
    data class Required(val authenticationStrength: UserAuthenticationStrength, val timeout: Duration) : UserAuthenticationPolicy
}

sealed interface UserAuthenticationStrength {
    object Weak : UserAuthenticationStrength
    object Strong : UserAuthenticationStrength
}

enum class Digests {
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
    NONE,
    RSA_PKCS1,
    RSA_PSS,
}

enum class KeyAlgorithm {
    AES,
    RSA
}

enum class BlockMode {
    UNDEFINED,
    ECB,
    CBC,
    CTR,
    GCM
}
