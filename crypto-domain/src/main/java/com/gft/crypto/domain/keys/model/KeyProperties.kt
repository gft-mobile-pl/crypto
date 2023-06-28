package com.gft.crypto.domain.keys.model

import com.gft.crypto.domain.common.model.CryptographicOperationParams
import kotlin.time.Duration

data class KeyProperties(
    val purposes: Set<KeyPurpose>,
    val keySize: Int,
    val unlockPolicy: UnlockPolicy,
    val userAuthenticationPolicy: UserAuthenticationPolicy,
    val supportedOperationParams: CryptographicOperationParams
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

