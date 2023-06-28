package com.gft.crypto.framework.keys.repositories

import android.annotation.SuppressLint
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.common.model.UsageScope
import com.gft.crypto.domain.keys.model.UserAuthenticationPolicy
import com.gft.crypto.domain.keys.repositories.KeysRepository
import com.gft.crypto.domain.keys.services.KeyPropertiesExtractor
import com.gft.crypto.domain.keys.services.KeyPropertiesProvider
import com.gft.crypto.framework.keys.utils.assertIsAndroidKeyStore
import com.gft.crypto.framework.keys.utils.resolveComplementaryPublicPurposes
import com.gft.crypto.framework.keys.utils.toNativeBlockMode
import com.gft.crypto.framework.keys.utils.toNativeDigest
import com.gft.crypto.framework.keys.utils.toNativeKeyPurpose
import com.gft.crypto.framework.keys.utils.toNativePadding
import com.gft.crypto.framework.keys.utils.toUnlockRequired
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.KeyGenerator
import kotlin.time.Duration
import kotlin.time.DurationUnit
import android.security.keystore.KeyProperties as NativeKeyProperties

open class OsBackedKeysRepository<T : UsageScope>(
    private val keyStore: KeyStore,
    private val keyPropertiesProvider: KeyPropertiesProvider<in T>,
    private val keyPropertiesExtractor: KeyPropertiesExtractor
) : KeysRepository<T> {
    init {
        keyStore.assertIsAndroidKeyStore()
    }

    override fun <R : T> createKey(alias: String, usageScope: R) {
        if (containsKey(alias)) {
            throw IllegalStateException("Key with alias $alias is already registered in the repository.")
        }
        val keyProperties = keyPropertiesProvider.getKeyProperties(usageScope)
        val keyGenParameterSpec = keyProperties.toKeyGenParameterSpec(alias)
        when (keyProperties.supportedOperationParams.algorithm) {
            Algorithm.AES -> {
                KeyGenerator
                    .getInstance(NativeKeyProperties.KEY_ALGORITHM_AES, keyStore.provider.name)
                    .apply {
                        init(keyGenParameterSpec)
                    }
                    .generateKey()
            }

            Algorithm.RSA -> {
                KeyPairGenerator
                    .getInstance(
                        NativeKeyProperties.KEY_ALGORITHM_RSA, keyStore.provider.name
                    )
                    .apply {
                        initialize(keyGenParameterSpec)
                    }
                    .generateKeyPair()
            }
        }
    }

    override fun getKey(alias: String): Set<KeyContainer> {
        if (!keyStore.containsAlias(alias)) {
            throw IllegalArgumentException("There is not key with alias $alias registered in the repository.")
        }
        return when {
            keyStore.entryInstanceOf(alias, KeyStore.SecretKeyEntry::class.java) -> {
                val secretKey = keyStore.getKey(alias, null)
                val keyProperties = keyPropertiesExtractor.resolveKeyProperties(secretKey)
                setOf(
                    KeyContainer(
                        key = secretKey,
                        keyPurposes = keyProperties.purposes
                    )
                )
            }

            keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry::class.java) -> {
                val publicKey = keyStore.getCertificate(alias).publicKey
                val privateKey = keyStore.getKey(alias, null)
                val keyProperties = keyPropertiesExtractor.resolveKeyProperties(privateKey)
                setOf(
                    KeyContainer(
                        key = publicKey,
                        keyPurposes = keyProperties.purposes.resolveComplementaryPublicPurposes()
                    ),
                    KeyContainer(
                        key = keyStore.getKey(alias, null),
                        keyPurposes = keyProperties.purposes
                    )
                )
            }

            else -> throw IllegalStateException("Not supported key stored with $alias alias.")
        }
    }

    override fun deleteKey(alias: String) {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    override fun containsKey(alias: String) = keyStore.containsAlias(alias)
}

@SuppressLint("WrongConstant")
private fun KeyProperties.toKeyGenParameterSpec(alias: String) = KeyGenParameterSpec
    .Builder(
        alias,
        purposes.sumOf { purpose -> purpose.toNativeKeyPurpose() }
    )
    .apply {
        setKeySize(keySize)
        with(supportedOperationParams) {
            if (digests != null) {
                setDigests(digests!!.toNativeDigest())
            }
            if (blockModes != null) {
                setBlockModes(blockModes!!.toNativeBlockMode())
            }
            if (signaturePaddings != null) {
                setSignaturePaddings(signaturePaddings!!.toNativePadding())
            }
            if (encryptionPaddings != null) {
                setEncryptionPaddings(encryptionPaddings!!.toNativePadding())
            }
        }
        when (val authenticationPolicy = userAuthenticationPolicy) {
            is UserAuthenticationPolicy.Required -> {
                if (authenticationPolicy.timeout <= Duration.ZERO) {
                    throw IllegalArgumentException("timeout value of UserAuthenticationPolicy.Required should be greater than 0.")
                }
                setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(
                        authenticationPolicy.timeout.toInt(DurationUnit.SECONDS),
                        NativeKeyProperties.AUTH_DEVICE_CREDENTIAL + NativeKeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(
                        authenticationPolicy.timeout.toInt(DurationUnit.SECONDS),
                    )
                }
            }

            is UserAuthenticationPolicy.RequiredAfterBoot -> {
                setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(
                        Int.MAX_VALUE,
                        NativeKeyProperties.AUTH_DEVICE_CREDENTIAL + NativeKeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(Int.MAX_VALUE)
                }
            }

            is UserAuthenticationPolicy.BiometricAuthenticationRequiredOnEachUse -> {
                setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(0, NativeKeyProperties.AUTH_BIOMETRIC_STRONG)
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(-1)
                }
            }

            UserAuthenticationPolicy.NotRequired -> {
                setUserAuthenticationRequired(false)
            }
        }
        setUnlockedDeviceRequired(unlockPolicy.toUnlockRequired())
    }
    .build()