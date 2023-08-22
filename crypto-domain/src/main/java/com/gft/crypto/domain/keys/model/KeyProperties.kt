package com.gft.crypto.domain.keys.model

import com.gft.crypto.domain.common.model.Transformation
import kotlin.time.Duration

data class KeyProperties<SupportedTransformation : Transformation>(
    val keySize: Int,
    val unlockPolicy: UnlockPolicy,
    val userAuthenticationPolicy: UserAuthenticationPolicy,
    val randomizationPolicy: RandomizationPolicy,
    val supportedTransformation: SupportedTransformation
)

sealed interface UserAuthenticationPolicy {
    object NotRequired : UserAuthenticationPolicy
    object RequiredAfterBoot : UserAuthenticationPolicy
    object BiometricAuthenticationRequiredOnEachUse : UserAuthenticationPolicy
    data class Required(val timeout: Duration) : UserAuthenticationPolicy
}

sealed interface RandomizationPolicy {
    object Required : RandomizationPolicy
    object NotRequired : RandomizationPolicy
    object Unknown : RandomizationPolicy
}

sealed interface UnlockPolicy {
    object Required : UnlockPolicy
    object NotRequired : UnlockPolicy
    object Unknown : UnlockPolicy
}
