package com.gft.crypto.domain.keys.model

import com.gft.crypto.domain.common.model.Digest
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.SignaturePadding
import kotlin.time.Duration

data class KeyProperties(
    val purposes: Set<KeyPurpose>,
    val algorithm: Algorithm,
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

