package com.gft.crypto.services

import android.content.Context
import android.content.SharedPreferences
import com.gft.crypto.domain.keys.repositories.KeysRepository
import com.gft.crypto.domain.keys.services.KeysFactory
import com.gft.crypto.domain.wrapping.services.KeyWrapper
import com.gft.crypto.framework.keys.repositories.OsBackedKeysRepository
import com.gft.crypto.framework.keys.services.DefaultKeyPropertiesExtractor
import com.gft.crypto.framework.wrapping.services.DefaultKeyWrapper
import java.security.KeyStore

object CryptoServices {
    private var initialized = false

    val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    private val keyPropertiesExtractor = DefaultKeyPropertiesExtractor(keyStore = keyStore)
    private lateinit var sharedPreferences: SharedPreferences
    lateinit var keysRepository: KeysRepository
    lateinit var keyWrapper: KeyWrapper
    val keysFactory: KeysFactory = KeysFactory()

    @Synchronized
    fun init(applicationContext: Context) {
        if (initialized) return
        initialized = true

        sharedPreferences = applicationContext.getSharedPreferences("keyRepository", Context.MODE_PRIVATE)
        keysRepository = OsBackedKeysRepository(
            keyStore = keyStore,
            keyPropertiesExtractor = keyPropertiesExtractor,
            sharedPreferences = sharedPreferences
        )
        keyWrapper = DefaultKeyWrapper(keysRepository)
    }
}