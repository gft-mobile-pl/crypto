package com.gft.crypto.framework.keys.services

import android.security.keystore.KeyProperties
import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.common.model.CryptographicScope
import com.gft.crypto.domain.keys.services.KeyPropertiesProvider
import com.gft.crypto.domain.keys.services.KeysFactory
import com.gft.crypto.framework.keys.utils.resolveComplementaryPublicPurposes
import java.security.KeyPairGenerator
import javax.crypto.KeyGenerator

class DefaultKeysFactory<T : CryptographicScope>(
    private val keyPropertiesProvider: KeyPropertiesProvider<T>
) : KeysFactory<T> {
    override fun <R : T> generateKey(scope: R): Set<KeyContainer> {
        val keyProperties = keyPropertiesProvider.getKeyProperties(scope)
        return when (keyProperties.cryptographicProperties.algorithm) {
            Algorithm.AES -> {
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

            Algorithm.RSA -> {
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
