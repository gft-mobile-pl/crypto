package com.gft.crypto.services

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.encryption.services.DataCipher
import com.gft.crypto.domain.keys.model.KeyAlias
import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.keys.model.KeyStoreCompatibleDataEncryption
import com.gft.crypto.domain.keys.model.UnlockPolicy
import com.gft.crypto.domain.keys.model.UserAuthenticationPolicy
import com.gft.crypto.domain.keys.repositories.KeysRepository
import com.gft.crypto.domain.keys.services.KeysFactory
import com.gft.crypto.domain.wrapping.services.KeyWrapper
import com.gft.crypto.framework.encryption.services.DefaultDataCipher
import com.gft.crypto.framework.keys.repositories.OsBackedKeysRepository
import com.gft.crypto.framework.keys.services.DefaultKeyPropertiesExtractor
import com.gft.crypto.framework.storage.services.EncryptedSharedPreferencesProvider
import com.gft.crypto.framework.wrapping.services.DefaultKeyWrapper
import java.security.KeyStore

object CryptoServices {
    private var initialized = false

    val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    private val keyPropertiesExtractor = DefaultKeyPropertiesExtractor(keyStore = keyStore)
    private lateinit var sharedPreferencesProvider: EncryptedSharedPreferencesProvider
    lateinit var keysRepository: KeysRepository
    lateinit var keyWrapper: KeyWrapper
    lateinit var dataCipher: DataCipher
    val keysFactory: KeysFactory = KeysFactory()

    @Synchronized
    fun init(applicationContext: Context) {
        if (initialized) return
        initialized = true

        keysRepository = OsBackedKeysRepository(
            keyStore = keyStore,
            keyPropertiesExtractor = keyPropertiesExtractor,
            sharedPreferences = EncryptedSharedPreferences.create(
                "keysRepositoryFileName",
                "keysRepositoryMasterKey",
                applicationContext,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        )
        sharedPreferencesProvider = EncryptedSharedPreferencesProvider(applicationContext, keysRepository)
        keyWrapper = DefaultKeyWrapper(keysRepository)
        dataCipher = DefaultDataCipher(keysRepository)
    }
}
