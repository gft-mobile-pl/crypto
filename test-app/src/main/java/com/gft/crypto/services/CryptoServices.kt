package com.gft.crypto.services

import com.gft.crypto.domain.keys.repositories.KeysRepository
import com.gft.crypto.domain.keys.services.KeysFactory
import com.gft.crypto.framework.keys.repositories.OsBackedKeysRepository
import com.gft.crypto.framework.keys.services.DefaultKeyPropertiesExtractor
import com.gft.crypto.framework.keys.services.DefaultKeysFactory
import com.gft.crypto.model.TestAppKeyUsagesScopes
import java.security.KeyStore

object CryptoServices {
    val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    private val keyPropertiesProvider = DefaultKeyPropertiesProvider()
    private val keyPropertiesExtractor = DefaultKeyPropertiesExtractor(keyStore = keyStore)
    val keysRepository: KeysRepository<TestAppKeyUsagesScopes> = OsBackedKeysRepository(
        keyStore = keyStore,
        keyPropertiesProvider = keyPropertiesProvider,
        keyPropertiesExtractor = keyPropertiesExtractor
    )
    val keysFactory: KeysFactory<TestAppKeyUsagesScopes> = DefaultKeysFactory(
        keyPropertiesProvider
    )
}