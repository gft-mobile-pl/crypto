package com.gft.crypto.model

import com.gft.crypto.domain.keys.model.KeyUsageScope

sealed interface TestAppKeyUsagesScopes : KeyUsageScope {
    object EncryptingMessages : TestAppKeyUsagesScopes
    object SecuritySharedPreferences : TestAppKeyUsagesScopes
}