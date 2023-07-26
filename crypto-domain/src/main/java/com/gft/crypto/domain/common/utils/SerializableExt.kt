package com.gft.crypto.domain.common.utils

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.io.Serializable
import java.util.Base64

fun Serializable.serialize(): String = ByteArrayOutputStream()
    .use { serialObj ->
        ObjectOutputStream(serialObj).use { objStream ->
            objStream.writeObject(this)
        }
        Base64.getEncoder().encodeToString(serialObj.toByteArray())
    }

inline fun <reified T> String.deserialize(): T = ByteArrayInputStream(Base64.getDecoder().decode(this))
    .use { serialObj ->
        ObjectInputStream(serialObj).use { objStream ->
            objStream.readObject() as T
        }
    }
