package com.gft.crypto.services

import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.CryptographicOperationParams
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.keys.model.KeyPurpose
import com.gft.crypto.domain.keys.model.UnlockPolicy
import com.gft.crypto.domain.keys.model.UserAuthenticationPolicy
import com.gft.crypto.domain.keys.services.KeyPropertiesProvider
import com.gft.crypto.model.TestAppCryptographyUsageScope

class DefaultKeyPropertiesProvider : KeyPropertiesProvider<TestAppCryptographyUsageScope> {
    override fun getKeyProperties(usageScope: TestAppCryptographyUsageScope): KeyProperties = when (usageScope) {
        TestAppCryptographyUsageScope.EncryptingMessages -> KeyProperties(
            purposes = setOf(KeyPurpose.Decryption),
            keySize = 2048,
            unlockPolicy = UnlockPolicy.Required,
            userAuthenticationPolicy = UserAuthenticationPolicy.RequiredAfterBoot,
            supportedOperationParams = CryptographicOperationParams(
                algorithm = Algorithm.RSA,
                digests = null,
                encryptionPaddings = EncryptionPadding.RSA_PKCS1,
                signaturePaddings = null,
                blockModes = BlockMode.ECB
            )
        )

        TestAppCryptographyUsageScope.SecuritySharedPreferences -> KeyProperties(
            purposes = setOf(KeyPurpose.Encryption, KeyPurpose.Decryption),
            keySize = 256,
            unlockPolicy = UnlockPolicy.Required,
            userAuthenticationPolicy = UserAuthenticationPolicy.BiometricAuthenticationRequiredOnEachUse,
            supportedOperationParams = CryptographicOperationParams(
                algorithm = Algorithm.AES,
                digests = null,
                encryptionPaddings = EncryptionPadding.None,
                signaturePaddings = null,
                blockModes = BlockMode.GCM
            )
        )
    }
}