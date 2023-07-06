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
import com.gft.crypto.domain.common.model.Transformation
import com.gft.crypto.domain.keys.model.KeyAlias
import com.gft.crypto.domain.keys.model.KeyProperties
import com.gft.crypto.domain.keys.model.KeyStoreCompatibleDataEncryption
import com.gft.crypto.domain.keys.model.KeyStoreCompatibleKeyWrapping
import com.gft.crypto.domain.keys.model.KeyStoreCompatibleMessageSigning
import com.gft.crypto.domain.keys.model.UnlockPolicy
import com.gft.crypto.domain.keys.model.UserAuthenticationPolicy
import com.gft.crypto.domain.wrapping.model.WrappedKeyContainer
import com.gft.crypto.services.CryptoServices
import com.gft.crypto.services.CryptoServices.keyWrapper
import com.gft.crypto.services.CryptoServices.keysFactory
import com.gft.crypto.services.CryptoServices.keysRepository
import com.gft.crypto.ui.theme.CryptolibraryTheme

private val SharedPrefsKeyAlias = KeyAlias<Transformation.DataEncryption>("spkeyalias")
private val SharedPrefsKeyProperties = KeyProperties(
    keySize = 256,
    unlockPolicy = UnlockPolicy.Required,
    userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
    supportedTransformation = KeyStoreCompatibleDataEncryption.AES_GCM_NoPadding
)

private val EncryptorKeyAlias = KeyAlias<Transformation.DataEncryption>("enckeyalias")
private val EncryptorKeyProperties = KeyProperties(
    keySize = 2048,
    unlockPolicy = UnlockPolicy.Required,
    userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
    supportedTransformation = KeyStoreCompatibleDataEncryption.RSA_ECB_PKCS1Padding
)

private val MessageSigningAlias = KeyAlias<Transformation.MessageSigning>("messagesigningalias")
private val MessageSigningProperties = KeyProperties(
    keySize = 2048,
    unlockPolicy = UnlockPolicy.NotRequired,
    userAuthenticationPolicy = UserAuthenticationPolicy.NotRequired,
    supportedTransformation = KeyStoreCompatibleMessageSigning.SHA512_RSA
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        CryptoServices.init(applicationContext)

        super.onCreate(savedInstanceState)
        setContent {
            CryptolibraryTheme {
                Column(
                    modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Button(onClick = {
                        keysRepository.createKey(SharedPrefsKeyAlias, SharedPrefsKeyProperties)
                        keysRepository.createKey(EncryptorKeyAlias, EncryptorKeyProperties)
                        keysRepository.createKey(MessageSigningAlias, MessageSigningProperties)
                    }) {
                        Text(text = "Create keys")
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
                }
            }
        }
    }
}
