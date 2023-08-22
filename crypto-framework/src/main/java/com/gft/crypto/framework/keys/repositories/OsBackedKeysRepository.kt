package com.gft.crypto.framework.keys.repositories

import android.annotation.SuppressLint
import android.content.SharedPreferences
import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.common.model.BlockMode
import com.gft.crypto.domain.common.model.Digest
import com.gft.crypto.domain.common.model.EncryptionPadding
import com.gft.crypto.domain.common.model.SignaturePadding
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.keys.model.KeyAlias
import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.keys.model.KeyStoreCompatible
import com.gft.crypto.domain.keys.model.RandomizationPolicy
import com.gft.crypto.domain.keys.model.UnlockPolicy
import com.gft.crypto.domain.keys.model.UserAuthenticationPolicy
import com.gft.crypto.domain.keys.repositories.KeysRepository
import com.gft.crypto.domain.keys.services.KeyPropertiesExtractor
import com.gft.crypto.framework.keys.utils.assertIsAndroidKeyStore
import com.gft.crypto.framework.keys.utils.toKeyGenParameterSpec
import com.gft.crypto.framework.keys.utils.toNativeKeyAlgorithm
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.KeyGenerator

private const val ALIAS_TOKEN = "_alias"
private const val ALGORITHM_TOKEN = "_algorithm"
private const val DIGEST_TOKEN = "_digest"
private const val PADDING_TOKEN = "_padding"
private const val BLOCK_MODE_TOKEN = "_block_mode"
private const val CANONICAL_TRANSFORMATION_TOKEN = "_canonical_transformation"
private const val UNLOCK_REQUIRED_TOKEN = "_unlock_required"
private const val RANDOMIZATION_REQUIRED_TOKEN = "_randomization_policy"

open class OsBackedKeysRepository(
    private val keyStore: KeyStore,
    private val keyPropertiesExtractor: KeyPropertiesExtractor,
    private val sharedPreferences: SharedPreferences
) : KeysRepository {
    init {
        keyStore.assertIsAndroidKeyStore()
    }

    @Suppress("INAPPLICABLE_JVM_NAME")
    @JvmName("createDataEncryptionKey")
    override fun <T> createKey(
        alias: KeyAlias<Transformation.DataEncryption>,
        properties: KeyProperties<T>
    ) where T : Transformation.DataEncryption, T : KeyStoreCompatible = createAndStoreKey(alias, properties)

    @Suppress("INAPPLICABLE_JVM_NAME")
    @JvmName("createMessageSingingKey")
    override fun <T> createKey(
        alias: KeyAlias<Transformation.MessageSigning>,
        properties: KeyProperties<T>
    ) where T : Transformation.MessageSigning, T : KeyStoreCompatible = createAndStoreKey(alias, properties)

    @Suppress("INAPPLICABLE_JVM_NAME")
    @JvmName("createKeyWrappingKey")
    override fun <T> createKey(
        alias: KeyAlias<Transformation.KeyWrapping>,
        properties: KeyProperties<T>
    ) where T : Transformation.KeyWrapping, T : KeyStoreCompatible = createAndStoreKey(alias, properties)

    private fun createAndStoreKey(alias: KeyAlias<*>, keyProperties: KeyProperties<*>) {
        if (containsKey(alias)) {
            throw IllegalStateException("Key with alias ${alias.alias} is already registered in the repository.")
        }
        val keyGenParameterSpec = keyProperties.toKeyGenParameterSpec(alias.alias)
        when (keyProperties.supportedTransformation.algorithm) {
            Algorithm.RSA,
            Algorithm.ECDSA -> {
                KeyPairGenerator
                    .getInstance(keyProperties.supportedTransformation.algorithm.toNativeKeyAlgorithm(), keyStore.provider.name)
                    .apply { initialize(keyGenParameterSpec) }
                    .generateKeyPair()
            }

            else -> {
                KeyGenerator
                    .getInstance(keyProperties.supportedTransformation.algorithm.toNativeKeyAlgorithm(), keyStore.provider.name)
                    .apply { init(keyGenParameterSpec) }
                    .generateKey()
            }
        }

        sharedPreferences.edit()
            .putString("${alias.alias}$ALIAS_TOKEN", alias.alias)
            .putString("${alias.alias}$ALGORITHM_TOKEN", keyProperties.supportedTransformation.algorithm.name)
            .putBoolean("${alias.alias}$UNLOCK_REQUIRED_TOKEN", keyProperties.unlockPolicy == UnlockPolicy.Required)
            .putString("${alias.alias}$CANONICAL_TRANSFORMATION_TOKEN", keyProperties.supportedTransformation.canonicalTransformation)
            .putBoolean("${alias.alias}$RANDOMIZATION_REQUIRED_TOKEN", keyProperties.randomizationPolicy == RandomizationPolicy.Required)
            .apply {
                when (val transformation = keyProperties.supportedTransformation) {
                    is Transformation.DataEncryption -> {
                        putString("${alias.alias}$PADDING_TOKEN", transformation.padding.name)
                        putString("${alias.alias}$BLOCK_MODE_TOKEN", transformation.blockMode.name)
                        putString("${alias.alias}$DIGEST_TOKEN", transformation.digest.name)
                    }

                    is Transformation.KeyWrapping -> {
                        putString("${alias.alias}$PADDING_TOKEN", transformation.padding.name)
                        putString("${alias.alias}$BLOCK_MODE_TOKEN", transformation.blockMode.name)
                        putString("${alias.alias}$DIGEST_TOKEN", transformation.digest.name)
                    }

                    is Transformation.MessageSigning -> {
                        putString("${alias.alias}$PADDING_TOKEN", transformation.padding.name)
                        putString("${alias.alias}$DIGEST_TOKEN", transformation.digest.name)
                    }
                }
            }
            .apply()
    }

    @Suppress("UNCHECKED_CAST")
    override fun <T : Transformation> getKey(alias: KeyAlias<T>): Set<KeyContainer<T>> {
        if (!keyStore.containsAlias(alias.alias)) {
            throw IllegalArgumentException("There is not key with alias $alias registered in the repository.")
        }

        return when {
            keyStore.entryInstanceOf(alias.alias, KeyStore.SecretKeyEntry::class.java) -> {
                val secretKey = keyStore.getKey(alias.alias, null)
                val keyProperties = keyPropertiesExtractor
                    .resolveKeyProperties(secretKey)
                    .updateWithDataFromSharedPreferences(alias.alias)
                setOf(
                    KeyContainer(
                        key = secretKey,
                        properties = keyProperties as KeyProperties<T>
                    )
                )
            }

            keyStore.entryInstanceOf(alias.alias, KeyStore.PrivateKeyEntry::class.java) -> {
                val publicKey = keyStore.getCertificate(alias.alias).publicKey
                val privateKey = keyStore.getKey(alias.alias, null)
                val keyProperties = keyPropertiesExtractor
                    .resolveKeyProperties(privateKey)
                    .updateWithDataFromSharedPreferences(alias.alias)
                setOf(
                    KeyContainer(
                        key = privateKey,
                        properties = keyProperties as KeyProperties<T>
                    ),
                    KeyContainer(
                        key = publicKey,
                        properties = keyProperties.copy(
                            // public keys never require user authentication
                            userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired
                        )
                    )
                )
            }

            else -> throw IllegalStateException("Not supported key stored with $alias alias.")
        }
    }

    override fun deleteKey(alias: KeyAlias<*>) {
        if (!keyStore.containsAlias(alias.alias)) return
        keyStore.deleteEntry(alias.alias)
        sharedPreferences.edit()
            .remove("${alias.alias}$ALIAS_TOKEN")
            .remove("${alias.alias}$ALGORITHM_TOKEN")
            .remove("${alias.alias}$DIGEST_TOKEN")
            .remove("${alias.alias}$BLOCK_MODE_TOKEN")
            .remove("${alias.alias}$PADDING_TOKEN")
            .remove("${alias.alias}$CANONICAL_TRANSFORMATION_TOKEN")
            .remove("${alias.alias}$UNLOCK_REQUIRED_TOKEN")
            .remove("${alias.alias}$RANDOMIZATION_REQUIRED_TOKEN")
            .apply()
    }

    override fun containsKey(alias: KeyAlias<*>) = keyStore.containsAlias(alias.alias)

    @SuppressLint("ApplySharedPref")
    override fun clear() {
        sharedPreferences.all.forEach { (key, value) ->
            if (key.contains(ALIAS_TOKEN)) {
                val alias = value as String
                deleteKey(KeyAlias<Transformation>(alias))
            }
        }
        sharedPreferences.edit().clear().commit()
    }

    private fun KeyProperties<*>.updateWithDataFromSharedPreferences(keyAlias: String): KeyProperties<*> {
        val algorithm = Algorithm.valueOf(sharedPreferences.getString("${keyAlias}$ALGORITHM_TOKEN", "")!!)
        val unlockPolicy = sharedPreferences.getBoolean("${keyAlias}$UNLOCK_REQUIRED_TOKEN", false)
            .let { required -> if (required) UnlockPolicy.Required else UnlockPolicy.NotRequired }
        val randomizationPolicy = sharedPreferences.getBoolean("${keyAlias}$RANDOMIZATION_REQUIRED_TOKEN", false)
            .let { required -> if (required) RandomizationPolicy.Required else RandomizationPolicy.NotRequired }
        val canonicalTransformation = sharedPreferences.getString("${keyAlias}$CANONICAL_TRANSFORMATION_TOKEN", "")!!
        val effectiveTransformation = when (supportedTransformation) {
            is Transformation.DataEncryption -> {
                GeneralDataEncryption(
                    algorithm,
                    BlockMode.valueOf(sharedPreferences.getString("${keyAlias}$BLOCK_MODE_TOKEN", "")!!),
                    Digest.valueOf(sharedPreferences.getString("${keyAlias}$DIGEST_TOKEN", "")!!),
                    EncryptionPadding.valueOf(sharedPreferences.getString("${keyAlias}$PADDING_TOKEN", "")!!),
                    canonicalTransformation
                )
            }

            is Transformation.KeyWrapping -> GeneralKeyWrapping(
                algorithm,
                BlockMode.valueOf(sharedPreferences.getString("${keyAlias}$BLOCK_MODE_TOKEN", "")!!),
                Digest.valueOf(sharedPreferences.getString("${keyAlias}$DIGEST_TOKEN", "")!!),
                EncryptionPadding.valueOf(sharedPreferences.getString("${keyAlias}$PADDING_TOKEN", "")!!),
                canonicalTransformation
            )

            is Transformation.MessageSigning -> GeneralMessageSigning(
                algorithm,
                Digest.valueOf(sharedPreferences.getString("${keyAlias}$DIGEST_TOKEN", "")!!),
                SignaturePadding.valueOf(sharedPreferences.getString("${keyAlias}$PADDING_TOKEN", "")!!),
                canonicalTransformation
            )
        }
        @Suppress("UNCHECKED_CAST")
        return (this as KeyProperties<Transformation>).copy(
            unlockPolicy = unlockPolicy,
            randomizationPolicy = randomizationPolicy,
            supportedTransformation = effectiveTransformation
        )
    }
}

private class GeneralDataEncryption(
    algorithm: Algorithm,
    blockMode: BlockMode,
    digest: Digest,
    padding: EncryptionPadding,
    override val canonicalTransformation: String
) : Transformation.DataEncryption(algorithm, blockMode, digest, padding)

private class GeneralKeyWrapping(
    algorithm: Algorithm,
    blockMode: BlockMode,
    digest: Digest,
    padding: EncryptionPadding,
    override val canonicalTransformation: String
) : Transformation.KeyWrapping(algorithm, blockMode, digest, padding)

private class GeneralMessageSigning(
    algorithm: Algorithm,
    digest: Digest,
    padding: SignaturePadding,
    override val canonicalTransformation: String
) : Transformation.MessageSigning(algorithm, digest, padding)
