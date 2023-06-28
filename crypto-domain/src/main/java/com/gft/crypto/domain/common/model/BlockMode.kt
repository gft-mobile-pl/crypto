package com.gft.crypto.domain.common.model

sealed interface BlockMode {
    object ECB : BlockMode
    object CBC : BlockMode
    object CTR : BlockMode
    object GCM : BlockMode
}