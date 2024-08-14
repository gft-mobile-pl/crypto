package com.gft.crypto.keys.repositories

import com.gft.crypto.common.model.Transformation
import com.gft.crypto.common.model.Transformation.DataEncryption
import com.gft.crypto.common.model.Transformation.KeyWrapping
import com.gft.crypto.common.model.Transformation.MessageSigning
import com.gft.crypto.keys.model.MissingKeyException
import com.gft.crypto.keys.model.UnsupportedKeyException
import com.gft.crypto.keys.model.KeyAlias
import com.gft.crypto.keys.model.KeyContainer
import com.gft.crypto.keys.model.KeyProperties
import com.gft.crypto.keys.model.KeyStoreCompatible
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException

interface KeysRepository {
    fun containsKey(alias: KeyAlias<*>): Boolean

    @Suppress("INAPPLICABLE_JVM_NAME")
    @JvmName("createMessageSingingKey")
    fun <T> createKey(alias: KeyAlias<MessageSigning>, properties: KeyProperties<T>) where T : KeyStoreCompatible, T : MessageSigning

    @Suppress("INAPPLICABLE_JVM_NAME")
    @JvmName("createDataEncryptionKey")
    fun <T> createKey(alias: KeyAlias<DataEncryption>, properties: KeyProperties<T>) where T : KeyStoreCompatible, T : DataEncryption

    @Suppress("INAPPLICABLE_JVM_NAME")
    @JvmName("createKeyWrappingKey")
    fun <T> createKey(alias: KeyAlias<KeyWrapping>, properties: KeyProperties<T>) where T : KeyStoreCompatible, T : KeyWrapping

    @Throws(
        KeyStoreException::class,
        NoSuchAlgorithmException::class,
        UnrecoverableKeyException::class,
        MissingKeyException::class,
        UnsupportedKeyException::class
    )
    fun <T> getKey(alias: KeyAlias<T>): Set<KeyContainer<T>> where T : Transformation

    fun deleteKey(alias: KeyAlias<*>)

    fun clear()
}
