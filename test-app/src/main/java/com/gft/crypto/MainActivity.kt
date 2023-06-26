package com.gft.crypto

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.gft.crypto.ui.theme.CryptolibraryTheme
import java.security.KeyStore

private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
    load(null)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CryptolibraryTheme {

            }
        }

        println("#Test keyStore = $keyStore")
    }
}