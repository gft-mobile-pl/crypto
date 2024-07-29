package com.gft.crypto.wrapping.services

import com.gft.crypto.common.model.CryptographicOperation
import com.gft.crypto.common.model.Transformation.KeyWrapping
import com.gft.crypto.keys.model.KeyAlias
import com.gft.crypto.wrapping.model.WrappedKeyContainer
import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.SecretKey

interface KeyWrapper {
    fun wrap(alias: KeyAlias<KeyWrapping>, keyToWrap: Key): CryptographicOperation<Cipher, WrappedKeyContainer>
    fun wrap(key: SecretKey, transformation: KeyWrapping, keyToWrap: Key): CryptographicOperation<Cipher, WrappedKeyContainer>
    fun wrap(key: PublicKey, transformation: KeyWrapping, keyToWrap: Key): CryptographicOperation<Cipher, WrappedKeyContainer>

    fun unwrap(
        alias: KeyAlias<KeyWrapping>,
        wrappedKeyData: WrappedKeyContainer
    ): CryptographicOperation<Cipher, Key>

    fun unwrap(
        key: SecretKey,
        transformation: KeyWrapping,
        wrappedKeyData: WrappedKeyContainer,
    ): CryptographicOperation<Cipher, Key>

    fun unwrap(
        key: PrivateKey,
        transformation: KeyWrapping,
        wrappedKeyData: WrappedKeyContainer,
    ): CryptographicOperation<Cipher, Key>
}
