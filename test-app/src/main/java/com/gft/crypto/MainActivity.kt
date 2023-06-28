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
import com.gft.crypto.model.TestAppCryptographyUsageScope
import com.gft.crypto.services.CryptoServices
import com.gft.crypto.services.CryptoServices.keysRepository
import com.gft.crypto.ui.theme.CryptolibraryTheme
import java.security.KeyStore

private const val SharedPrefsKeyAlias = "spkeyalias"
private const val EncryptorKeyAlias = "enckeyalias"

private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
    load(null)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CryptolibraryTheme {
                Column(
                    modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Button(onClick = {
                        keysRepository.createKey(SharedPrefsKeyAlias, TestAppCryptographyUsageScope.SecuritySharedPreferences)
                        keysRepository.createKey(EncryptorKeyAlias, TestAppCryptographyUsageScope.EncryptingMessages)
                    }) {
                        Text(text = "Create 2 keys")
                    }

                    Button(onClick = {
                        println("#Test SharedPrefsKeyAlias = ${keysRepository.getKey(SharedPrefsKeyAlias)}")
                        println("#Test EncryptorKeyAlias = ${keysRepository.getKey(EncryptorKeyAlias)}")
                    }) {
                        Text(text = "Get 2 keys")
                    }

                    Button(onClick = {
                        CryptoServices.keyStore.aliases().toList().forEach {
                            println("#Test Deleting key entry... $it")
                            CryptoServices.keyStore.deleteEntry(it)
                        }

                    }) {
                        Text(text = "Clear all")
                    }
                }
            }
        }

        println("#Test keyStore = ${keyStore.provider.name}")
    }
}