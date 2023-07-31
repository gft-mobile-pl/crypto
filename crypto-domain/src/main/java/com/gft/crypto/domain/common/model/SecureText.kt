package com.gft.crypto.domain.common.model

import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference
import java.util.Arrays
import java.util.UUID

private val EMPTY_CHAR_ARRAY = CharArray(0)

/**
 * Immutable container for keeping text in char arrays.
 */
class SecureText(
    text: CharArray,
    val name: String = UUID.randomUUID().toString()
) {
    private var isCleared = false

    constructor(
        text: Char,
        name: String = UUID.randomUUID().toString()
    ) : this(
        text = CharArray(1).also { array -> array[0] = text },
        name = name
    )

    private var _text: CharArrayContainer = CharArrayContainer(text)
    val text: CharArray
        get() = _text.characters

    init {
        references.add(SecureTextReference(this, _text))
    }

    val size: Int
        get() = text.size

    fun clear() {
        isCleared = true
        text.clear()
        _text.characters = EMPTY_CHAR_ARRAY
    }

    override fun toString(): String {
        return "SecureText(name='$name')"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecureText) return false

        if (name != other.name) return false
        if (isCleared != other.isCleared) return false
        if (!_text.characters.contentEquals(other._text.characters)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = name.hashCode()
        result = 31 * result + isCleared.hashCode()
        result = 31 * result + _text.hashCode()
        return result
    }

    private class CharArrayContainer(
        var characters: CharArray
    )

    private class SecureTextReference(
        secureText: SecureText,
        val text: CharArrayContainer
    ) : WeakReference<SecureText>(secureText, referencesQueue)

    private companion object {
        val referencesQueue = ReferenceQueue<SecureText>()
        val references = mutableListOf<SecureTextReference>()

        init {
            Thread(
                {
                    while (true) {
                        val reference = referencesQueue.remove() as SecureTextReference
                        reference.text.characters.clear()
                        references.remove(reference)
                    }
                },
                "SecureTextMaintenanceThread"
            ).apply { start() }
        }
    }
}

private fun CharArray.clear() = Arrays.fill(this, Char(0))

fun SecureText.append(text: CharArray, clearInput: Boolean = true): SecureText {
    return SecureText(
        text = this.text + text,
        name = this.name
    ).also {
        if (clearInput) {
            text.clear()
            this.clear()
        }
    }
}

fun SecureText.append(character: Char, clearInput: Boolean = true): SecureText = append(
    text = CharArray(1).apply { this[0] = character },
    clearInput = clearInput
)

fun SecureText.dropLast(clearInput: Boolean = true): SecureText {
    if (this.size == 0) return SecureText(
        text = CharArray(0),
        name = this.name
    ).also {
        if (clearInput) {
            this.clear()
        }
    }

    return SecureText(
        text = CharArray(this.size - 1),
        name = this.name
    ).also { newInstance ->
        for (i in 0 until newInstance.size) {
            newInstance.text[i] = this.text[i]
        }
        if (clearInput) {
            this.clear()
        }
    }
}

fun SecureText.replace(text: CharArray, clearInput: Boolean = true): SecureText {
    return SecureText(
        text = text.clone(),
        name = this.name
    ).also {
        if (clearInput) {
            text.clear()
            this.clear()
        }
    }
}
