package com.gft.crypto.framework.storage.services

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import com.gft.crypto.common.model.Transformation
import com.gft.crypto.keys.model.KeyAlias
import com.gft.crypto.keys.model.KeyProperties
import com.gft.crypto.keys.model.KeyStoreCompatibleDataEncryption
import com.gft.crypto.keys.model.RandomizationPolicy
import com.gft.crypto.keys.model.UnlockPolicy
import com.gft.crypto.keys.model.UserAuthenticationPolicy
import com.gft.crypto.keys.repositories.KeysRepository
import java.security.InvalidKeyException
import java.security.KeyStoreException

private const val DEFAULT_AES_KEY_SIZE = 256

class EncryptedSharedPreferencesProvider(
    private val applicationContext: Context,
    private val keysRepository: KeysRepository
) {

    fun getEncryptedSharedPreferences(
        fileName: String,
        masterKeyAlias: KeyAlias<Transformation.DataEncryption>,
        unlockPolicy: UnlockPolicy = UnlockPolicy.NotRequired,
        userAuthenticationPolicy: UserAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
        randomizationPolicy: RandomizationPolicy = RandomizationPolicy.Required,
        recreateCorruptedSharedPreferences: Boolean = false
    ): SharedPreferences {
        initMasterKey(masterKeyAlias, unlockPolicy, userAuthenticationPolicy, randomizationPolicy)

        try {
            return createEncryptedSharedPreferences(applicationContext, fileName, masterKeyAlias)
        } catch (error: Throwable) {
            if (recreateCorruptedSharedPreferences && !error.isKeyStoreException()) {
                applicationContext.deleteSharedPreferences(fileName)
            } else throw error
        }
        return createEncryptedSharedPreferences(applicationContext, fileName, masterKeyAlias)
    }

    private fun initMasterKey(
        masterKeyAlias: KeyAlias<Transformation.DataEncryption>,
        unlockPolicy: UnlockPolicy,
        userAuthenticationPolicy: UserAuthenticationPolicy,
        randomizationPolicy: RandomizationPolicy
    ) {
        if (keysRepository.containsKey(masterKeyAlias)) return

        val keyProperties = KeyProperties(
            keySize = DEFAULT_AES_KEY_SIZE,
            unlockPolicy = unlockPolicy,
            userAuthenticationPolicy = userAuthenticationPolicy,
            randomizationPolicy = randomizationPolicy,
            supportedTransformation = KeyStoreCompatibleDataEncryption.AES_GCM_NoPadding
        )
        keysRepository.createKey(masterKeyAlias, keyProperties)
    }

    private fun createEncryptedSharedPreferences(
        applicationContext: Context,
        fileName: String,
        masterKeyAlias: KeyAlias<Transformation.DataEncryption>
    ) = EncryptedSharedPreferences.create(
        fileName,
        masterKeyAlias.alias,
        applicationContext,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private fun Throwable.isKeyStoreException(): Boolean {
        var currentThrowable: Throwable? = this
        while (currentThrowable != null) {
            if (currentThrowable is KeyStoreException || currentThrowable is InvalidKeyException) {
                return true
            }
            currentThrowable = currentThrowable.cause
        }
        return false
    }
}
