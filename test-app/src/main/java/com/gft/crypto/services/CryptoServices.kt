package com.gft.crypto.services

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import com.gft.crypto.encryption.services.DataCipher
import com.gft.crypto.keys.repositories.KeysRepository
import com.gft.crypto.keys.services.KeysFactory
import com.gft.crypto.keys.services.PublicKeyParser
import com.gft.crypto.pin.services.PinBlockDecoder
import com.gft.crypto.pin.services.PinBlockGenerator
import com.gft.crypto.signing.services.SignatureVerifier
import com.gft.crypto.signing.services.Signer
import com.gft.crypto.wrapping.services.KeyWrapper
import com.gft.crypto.framework.encryption.services.DefaultDataCipher
import com.gft.crypto.framework.keys.repositories.OsBackedKeysRepository
import com.gft.crypto.framework.keys.services.DefaultKeyPropertiesExtractor
import com.gft.crypto.framework.keys.services.DefaultPublicKeyParser
import com.gft.crypto.framework.signing.services.DefaultSigner
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
    lateinit var signer: Signer
    lateinit var signatureVerifier: SignatureVerifier
    lateinit var pinBlockGenerator: PinBlockGenerator
    lateinit var pinBlockDecoder: PinBlockDecoder
    lateinit var parser: PublicKeyParser
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
        signer = DefaultSigner(keysRepository)
        signatureVerifier = DefaultSigner(keysRepository)
        pinBlockGenerator = PinBlockGenerator(dataCipher)
        parser = DefaultPublicKeyParser()
        pinBlockDecoder = PinBlockDecoder(dataCipher)
    }
}
