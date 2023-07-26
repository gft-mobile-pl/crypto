package com.gft.crypto.domain.encryption.services

import com.gft.crypto.domain.common.model.CryptographicOperation
import com.gft.crypto.domain.common.model.Transformation.DataEncryption
import com.gft.crypto.domain.encryption.model.EncryptedData
import com.gft.crypto.domain.keys.model.KeyAlias
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.SecretKey

interface DataCipher {
    fun encrypt(alias: KeyAlias<DataEncryption>, data: ByteArray): CryptographicOperation<Cipher, EncryptedData>
    fun encrypt(key: SecretKey, transformation: DataEncryption, data: ByteArray): CryptographicOperation<Cipher, EncryptedData>
    fun encrypt(key: PublicKey, transformation: DataEncryption, data: ByteArray): CryptographicOperation<Cipher, EncryptedData>

    fun decrypt(alias: KeyAlias<DataEncryption>, encryptedData: EncryptedData): CryptographicOperation<Cipher, ByteArray>
    fun decrypt(key: SecretKey, transformation: DataEncryption, encryptedData: EncryptedData): CryptographicOperation<Cipher, ByteArray>
    fun decrypt(key: PrivateKey, transformation: DataEncryption, encryptedData: EncryptedData ): CryptographicOperation<Cipher, ByteArray>
}
