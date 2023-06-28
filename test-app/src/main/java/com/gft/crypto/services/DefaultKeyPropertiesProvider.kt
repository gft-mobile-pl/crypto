package com.gft.crypto.services

import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.keys.model.KeyPurpose
import com.gft.crypto.domain.keys.model.UnlockPolicy
import com.gft.crypto.domain.keys.model.UserAuthenticationPolicy
import com.gft.crypto.domain.keys.services.KeyPropertiesProvider
import com.gft.crypto.model.TestAppKeyUsagesScopes

class DefaultKeyPropertiesProvider : KeyPropertiesProvider<TestAppKeyUsagesScopes> {
    override fun getKeyProperties(usageScope: TestAppKeyUsagesScopes): KeyProperties = when (usageScope) {
        TestAppKeyUsagesScopes.EncryptingMessages -> KeyProperties(
            purposes = setOf(KeyPurpose.Decryption),
            algorithm = Algorithm.RSA,
            keySize = 2048,
            unlockPolicy = UnlockPolicy.Required,
            userAuthenticationPolicy = UserAuthenticationPolicy.RequiredAfterBoot,
            digests = emptySet(),
            encryptionPaddings = setOf(EncryptionPadding.RSA_PKCS1),
            signaturePaddings = emptySet(),
            blockModes = setOf(BlockMode.ECB)
        )

        TestAppKeyUsagesScopes.SecuritySharedPreferences -> KeyProperties(
            purposes = setOf(KeyPurpose.Encryption, KeyPurpose.Decryption),
            algorithm = Algorithm.AES,
            keySize = 256,
            unlockPolicy = UnlockPolicy.Required,
            userAuthenticationPolicy = UserAuthenticationPolicy.BiometricAuthenticationRequiredOnEachUse,
            digests = emptySet(),
            encryptionPaddings = setOf(EncryptionPadding.NONE),
            signaturePaddings = emptySet(),
            blockModes = setOf(BlockMode.GCM)
        )
    }
}