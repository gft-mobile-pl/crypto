package com.gft.crypto.model

import com.gft.crypto.domain.common.model.CryptographicScope

sealed interface TestAppKeyUsagesScopes : CryptographicScope {
    object EncryptingMessages : TestAppKeyUsagesScopes
    object SecuritySharedPreferences : TestAppKeyUsagesScopes
}