package com.gft.crypto.framework.keys.utils

import java.security.KeyStore

private const val AndroidKeyStoreProviderName: String = "AndroidKeyStore"

fun KeyStore.assertIsAndroidKeyStore() {
    if (provider.name != AndroidKeyStoreProviderName) {
        throw AssertionError("Only native Android Key Store is supported!")
    }
}