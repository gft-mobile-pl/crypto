package com.gft.crypto.keys.model

import java.security.KeyStoreException

class MissingKeyException(
    alias: KeyAlias<*>
) : KeyStoreException("There is no key with alias ${alias.alias} registered in the repository.")

class UnsupportedKeyException(
    alias: KeyAlias<*>
) : KeyStoreException("Key with alias ${alias.alias} is not supported.")
