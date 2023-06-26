package com.gft.crypto.framework.keys.services

import android.security.keystore.KeyProperties
import com.gft.crypto.domain.keys.model.KeyAlgorithm
import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.keys.model.KeyUsageScope
import com.gft.crypto.domain.keys.services.KeyPropertiesProvider
import com.gft.crypto.domain.keys.services.KeysFactory
import com.gft.crypto.framework.keys.utils.resolveComplementaryPublicPurposes
import java.security.KeyPairGenerator
import javax.crypto.KeyGenerator

class DefaultKeysFactory<T : KeyUsageScope>(
    private val keyPropertiesProvider: KeyPropertiesProvider<T>
) : KeysFactory<T> {
    override fun <R : T> generateKey(usageScope: R): Set<KeyContainer> {
        val keyProperties = keyPropertiesProvider.getKeyProperties(usageScope)
        return when (keyProperties.algorithm) {
            KeyAlgorithm.AES -> {
                KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES)
                    .apply {
                        init(keyProperties.keySize)
                    }
                    .generateKey()
                    .let { secretKey ->
                        setOf(
                            KeyContainer(
                                key = secretKey,
                                keyPurposes = keyProperties.purposes
                            )
                        )
                    }
            }

            KeyAlgorithm.RSA -> {
                KeyPairGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_RSA)
                    .apply {
                        initialize(keyProperties.keySize)
                    }
                    .generateKeyPair()
                    .let { keyPair ->
                        setOf(
                            KeyContainer(
                                key = keyPair.public,
                                keyPurposes = keyProperties.purposes.resolveComplementaryPublicPurposes()
                            ),
                            KeyContainer(
                                key = keyPair.private,
                                keyPurposes = keyProperties.purposes
                            )
                        )
                    }
            }
        }
    }
}
