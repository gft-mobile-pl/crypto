package com.gft.crypto

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import com.gft.crypto.domain.common.model.Algorithm
import com.gft.crypto.domain.common.model.SecureText
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.common.model.append
import com.gft.crypto.domain.common.model.dropLast
import com.gft.crypto.domain.common.model.replace
import com.gft.crypto.domain.encryption.model.EncryptedData
import com.gft.crypto.domain.keys.model.KeyAlias
import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.keys.model.KeyStoreCompatibleDataEncryption
import com.gft.crypto.domain.keys.model.KeyStoreCompatibleDataEncryption.RSA_ECB_PKCS1Padding
import com.gft.crypto.domain.keys.model.KeyStoreCompatibleKeyWrapping
import com.gft.crypto.domain.keys.model.KeyStoreCompatibleMessageSigning
import com.gft.crypto.domain.keys.model.RandomizationPolicy
import com.gft.crypto.domain.keys.model.UnlockPolicy
import com.gft.crypto.domain.keys.model.UserAuthenticationPolicy
import com.gft.crypto.domain.wrapping.model.WrappedKeyContainer
import com.gft.crypto.services.CryptoServices
import com.gft.crypto.services.CryptoServices.dataCipher
import com.gft.crypto.services.CryptoServices.keyWrapper
import com.gft.crypto.services.CryptoServices.keysFactory
import com.gft.crypto.services.CryptoServices.keysRepository
import com.gft.crypto.services.CryptoServices.parser
import com.gft.crypto.services.CryptoServices.pinBlockGenerator
import com.gft.crypto.ui.theme.CryptolibraryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import javax.crypto.SecretKey

private val SharedPrefsKeyAlias = KeyAlias<Transformation.DataEncryption>("spkeyalias")
private val SharedPrefsKeyProperties = KeyProperties(
    keySize = 256,
    unlockPolicy = UnlockPolicy.Required,
    userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
    randomizationPolicy = RandomizationPolicy.Required,
    supportedTransformation = KeyStoreCompatibleDataEncryption.AES_GCM_NoPadding
)

private val EncryptorKeyAlias = KeyAlias<Transformation.DataEncryption>("enckeyalias")
private val EncryptorKeyProperties = KeyProperties(
    keySize = 2048,
    unlockPolicy = UnlockPolicy.Required,
    userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
    randomizationPolicy = RandomizationPolicy.Required,
    supportedTransformation = RSA_ECB_PKCS1Padding
)

private val MessageSigningAlias = KeyAlias<Transformation.MessageSigning>("messagesigningalias")
private val MessageSigningProperties = KeyProperties(
    keySize = 2048,
    unlockPolicy = UnlockPolicy.NotRequired,
    userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
    randomizationPolicy = RandomizationPolicy.Required,
    supportedTransformation = KeyStoreCompatibleMessageSigning.SHA512_RSA
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        CryptoServices.init(applicationContext)

        var secureText: SecureText?

        super.onCreate(savedInstanceState)
        setContent {
            CryptolibraryTheme {
                Column(
                    modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Button(onClick = {
                        println("#Test SecureText test started")
                        secureText = SecureText("password".toCharArray())
                        secureText = SecureText(Char(0))
                        secureText = secureText?.replace("ala ma kot".toCharArray())
                        secureText = secureText?.append("X".toCharArray().first())
                        secureText = secureText?.append("Y".toCharArray().first())
                        secureText = secureText?.append("Z".toCharArray().first())
                        secureText = secureText?.dropLast()
                        println("#Test after append/remove: ${secureText?.text?.contentToString()} / ${secureText?.size}")
                        secureText?.clear()
                        println("#Test after clear: ${secureText?.text?.contentToString()} / ${secureText?.size}")
                        secureText = null
                    }) {
                        Text(text = "Test SecureText")
                    }

                    Button(onClick = {
                        GlobalScope.launch(Dispatchers.IO) {
                            var message = "";
                            var count = 0
                            for (i in 0..30000) {
                                message += "Some not so long, not so short text."
                                count += message.length
                            }
                            System.gc()
                            println("#Test count = $count")
                        }
                    }) {
                        Text(text = "Stress memory")
                    }

                    Button(onClick = {
                        keysRepository.createKey(SharedPrefsKeyAlias, SharedPrefsKeyProperties)
                        keysRepository.createKey(EncryptorKeyAlias, EncryptorKeyProperties)
                        keysRepository.createKey(MessageSigningAlias, MessageSigningProperties)
                    }) {
                        Text(text = "Create keys")
                    }

                    Button(onClick = {
                        val message = "Ala ma kota 1234578901234567890." // 256 bits
                        val messageBytes = message.toByteArray(Charsets.UTF_8)
                        val transformation = KeyStoreCompatibleDataEncryption.AES_ECB_NoPadding
                        val alias = KeyAlias<Transformation.DataEncryption>("encryption_key")
                        try {
                            println("#Test ---------------------------------------------------------------------------")
                            print("#Test Adding encryption key supporting ${transformation.canonicalTransformation}... ")
                            keysRepository.createKey(
                                alias = alias,
                                properties = KeyProperties(
                                    keySize = if (transformation.algorithm == Algorithm.AES) 256 else 2048,
                                    unlockPolicy = UnlockPolicy.NotRequired,
                                    userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
                                    randomizationPolicy = RandomizationPolicy.NotRequired,
                                    supportedTransformation = transformation
                                )
                            )
                            println("COMPLETE")

                            repeat(10) {
                                print("#Test Encrypting with ${transformation.canonicalTransformation}... ")
                                val encryptedData = dataCipher.encrypt(alias, messageBytes).perform()
                                val encryptedDataString = encryptedData.toString()
                                println("COMPLETE $encryptedDataString")
                                print("#Test Decrypting with ${transformation.canonicalTransformation}... ")
                                val decryptedData = dataCipher.decrypt(alias, EncryptedData.valueOf(encryptedDataString)).perform()
                                println("COMPLETE (${decryptedData.toString(Charsets.UTF_8)})")
                            }
                        } catch (e: Throwable) {
                            println("FAILED")
                            println("#Test Error: ${e.message} / ${e.cause?.message}")
                        }

                        keysRepository.deleteKey(alias)
                    }
                    ) {
                        Text(text = "Encryption randomization test")
                    }

                    Button(onClick = {
                        val message = "Ala ma kota 1234578901234567890." // 256 bits
                        val messageBytes = message.toByteArray(Charsets.UTF_8)
                        var counter = 0
                        KeyStoreCompatibleDataEncryption.getAll().forEach { transformation ->
                            counter++

                            val alias = KeyAlias<Transformation.DataEncryption>("encryption_key_$counter")
                            try {
                                println("#Test ---------------------------------------------------------------------------")
                                print("#Test Adding encryption key supporting ${transformation.canonicalTransformation}... ")
                                keysRepository.createKey(
                                    alias = alias,
                                    properties = KeyProperties(
                                        keySize = if (transformation.algorithm == Algorithm.AES) 256 else 2048,
                                        unlockPolicy = UnlockPolicy.NotRequired,
                                        userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
                                        randomizationPolicy = RandomizationPolicy.NotRequired,
                                        supportedTransformation = transformation
                                    )
                                )
                                println("COMPLETE")

                                print("#Test Encrypting with ${transformation.canonicalTransformation}... ")
                                val encryptedData = dataCipher.encrypt(alias, messageBytes).perform()
                                val encryptedDataString = encryptedData.toString()
                                println("COMPLETE $encryptedDataString")
                                print("#Test Decrypting with ${transformation.canonicalTransformation}... ")
                                val decryptedData = dataCipher.decrypt(alias, EncryptedData.valueOf(encryptedDataString)).perform()
                                println("COMPLETE (${decryptedData.toString(Charsets.UTF_8)})")
                            } catch (e: Throwable) {
                                println("FAILED")
                                println("#Test Error: ${e.message} / ${e.cause?.message}")
                            }

                            keysRepository.deleteKey(alias)
                        }
                    }) {
                        Text(text = "Encrypt & Decrypt")
                    }

                    Button(onClick = {
                        var counter = 0
                        val keyToWrap = keysFactory.generateKey(256, KeyStoreCompatibleDataEncryption.AES_GCM_NoPadding).first()
                        KeyStoreCompatibleKeyWrapping.getAll().forEach { transformation ->
                            counter++

                            val alias = KeyAlias<Transformation.KeyWrapping>("wrapper_$counter")
                            try {
                                println("#Test ---------------------------------------------------------------------------")
                                print("#Test Adding wrapping key supporting ${transformation.canonicalTransformation}... ")
                                keysRepository.createKey(
                                    alias = alias,
                                    properties = KeyProperties(
                                        keySize = if (transformation.algorithm == Algorithm.AES) 256 else 2048,
                                        unlockPolicy = UnlockPolicy.NotRequired,
                                        userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
                                        randomizationPolicy = RandomizationPolicy.NotRequired,
                                        supportedTransformation = transformation
                                    )
                                )
                                println("COMPLETE")

                                print("#Test Wrapping with ${transformation.canonicalTransformation}... ")
                                val wrappedKey = keyWrapper.wrap(alias, keyToWrap).perform().toString()
                                println("COMPLETE $wrappedKey")
                                print("#Test Unwrapping with ${transformation.canonicalTransformation}... ")
                                val unwrappedKey = keyWrapper.unwrap(alias, WrappedKeyContainer.valueOf(wrappedKey)).perform()
                                println("COMPLETE ($unwrappedKey)")
                            } catch (e: Throwable) {
                                println("FAILED")
                                println("#Test Error: ${e.message} / ${e.cause?.message}")
                            }

                            keysRepository.deleteKey(alias)
                        }
                    }) {
                        Text(text = "Wrap & Unwrap test")
                    }

                    Button(onClick = {
                        println("#Test SharedPrefsKeyAlias = ${keysRepository.getKey(SharedPrefsKeyAlias)}")
                        println("#Test EncryptorKeyAlias = ${keysRepository.getKey(EncryptorKeyAlias)}")
                        println("#Test MessageSigningAlias = ${keysRepository.getKey(MessageSigningAlias)}")
                    }) {
                        Text(text = "Get keys")
                    }

                    Button(onClick = {
                        keysRepository.clear()
                    }) {
                        Text(text = "Clear all")
                    }

                    Button(onClick = {
                        println("#Test ---------------------------------------------------------------------------")
                        val pin = SecureText("1234".toCharArray())
                        val pan = SecureText("432198765432109870".toCharArray())
                        val transformation = KeyStoreCompatibleDataEncryption.AES_ECB_NoPadding
                        val encryptionKey = keysFactory.generateKey(128, transformation).first() as SecretKey
                        val encipheredPinBlock = pinBlockGenerator.generate(encryptionKey, transformation, pin, pan)
                        println("#Test encryptedPinBlock = ${encipheredPinBlock.pinBlock}")
                        println("#Test encryptionKey = ${encipheredPinBlock.encryptionKey.encoded.toString(Charsets.UTF_8)}")
                        println("#Test ---------------------------------------------------------------------------")
                    }) {
                        Text(text = "Generate Pin")
                    }

                    Button(onClick = {
                        println("#Test ---------------------------------------------------------------------------")
                        val textToEncrypt = "Test".toByteArray()
                        val publicKeyPem = """-----BEGIN PUBLIC KEY-----
                            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwG1czeb1jftfP276SgD
                            /Cpeof0ikosJxBt+ZjK65UMNV8gwI4MSGOswW50fngvF4tsvw8EXpitTgCDtPMC4
                            oTmTHIQviBcn2ryIOoX9sZJC0joJZuF93KmFIqdaXzt1FRg6Iu4SGO62h3S+2PP7
                            AVlFjKhaJ84DkAhj2+qlj54DH7oe8EO63gMsNdE1i/1HvF84HrE20mxAatqWgV8f
                            VCRzWky9bFUindzGNbl5krTDMZAq56I9NA4VTNnjBQ/RXWqd5fszvIJhIzlIpXpD
                            5uY9PwceH1g3cmMWqjRfXrbqxgojK/ce/XMdwIEqV4qYzx9DieIkE6hwAA1WJ0a/
                            IwIDAQAB
                            -----END PUBLIC KEY-----"""
                        val publicKey = parser.parse(publicKeyPem, Algorithm.RSA)
                        val encryptedData = dataCipher.encrypt(publicKey, RSA_ECB_PKCS1Padding, textToEncrypt).perform()
                        println("#Test encryptedData = ${encryptedData.data}")
                        println("#Test ---------------------------------------------------------------------------")
                    }) {
                        Text(text = "Parse Public Key")
                    }
                }
            }
        }
    }
}
