package com.gft.crypto.domain.keys.repositories

import com.gft.crypto.domain.keys.model.KeyStoreCompatible
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.common.model.Transformation.DataEncryption
import com.gft.crypto.domain.common.model.Transformation.KeyWrapping
import com.gft.crypto.domain.common.model.Transformation.MessageSigning
import com.gft.crypto.domain.keys.model.KeyAlias
import com.gft.crypto.domain.keys.model.KeyContainer
import com.gft.crypto.domain.keys.model.KeyProperties

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
    fun <T> getKey(alias: KeyAlias<T>): Set<KeyContainer<T>> where T : Transformation
    fun deleteKey(alias: KeyAlias<*>)
}
