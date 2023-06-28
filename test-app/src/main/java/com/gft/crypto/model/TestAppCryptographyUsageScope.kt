package com.gft.crypto.model

import com.gft.crypto.domain.common.model.UsageScope

sealed interface TestAppCryptographyUsageScope : UsageScope {
    object EncryptingMessages : TestAppCryptographyUsageScope
    object SecuritySharedPreferences : TestAppCryptographyUsageScope
}