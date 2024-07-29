package com.gft.crypto.common.model

sealed interface Transformation {
    val algorithm: Algorithm
    val canonicalTransformation: String

    open class MessageSigning(
        override val algorithm: Algorithm,
        val digest: Digest,
        val padding: SignaturePadding
    ) : Transformation {
        override val canonicalTransformation: String
            get() {
                val effectivePadding = when {
                    padding.name.equals(SignaturePadding.PKCS1.name, ignoreCase = true)
                        || padding.name.equals(SignaturePadding.NONE.name, ignoreCase = true) -> ""

                    else -> padding.name
                }
                return CANONICAL_PATTERN
                    .replace(ALGORITHM_TOKEN, algorithm.name)
                    .replace(DIGEST_TOKEN, digest.name)
                    .replace(PADDING_TOKEN, effectivePadding)
                    .replace(Regex("/$"), "") // TODO: test this replacement
            }

        override fun toString(): String {
            return "MessageSigning(algorithm=$algorithm, digest=$digest, padding=$padding, canonicalTransformation='$canonicalTransformation')"
        }

        protected companion object {
            const val ALGORITHM_TOKEN = "[ALGORITHM]"
            const val DIGEST_TOKEN = "[DIGEST]"
            const val PADDING_TOKEN = "[PADDING]"
            const val CANONICAL_PATTERN = "${DIGEST_TOKEN}with${ALGORITHM_TOKEN}/${PADDING_TOKEN}"
        }
    }

    open class DataEncryption(
        override val algorithm: Algorithm,
        val blockMode: BlockMode,
        val digest: Digest,
        val padding: EncryptionPadding
    ) : Transformation {

        override val canonicalTransformation: String
            get() = CANONICAL_PATTERN
                .replace(ALGORITHM_TOKEN, algorithm.name)
                .replace(BLOCK_MODE_TOKEN, blockMode.name)
                .replace(PADDING_TOKEN, padding.name)

        override fun toString(): String {
            return "DataEncryption(algorithm=$algorithm, blockMode=$blockMode, digest=$digest, padding=$padding, canonicalTransformation='$canonicalTransformation')"
        }

        protected companion object {
            const val ALGORITHM_TOKEN = "[ALGORITHM]"
            const val BLOCK_MODE_TOKEN = "[BLOCK_MODE]"
            const val PADDING_TOKEN = "[PADDING]"
            const val CANONICAL_PATTERN = "${ALGORITHM_TOKEN}/${BLOCK_MODE_TOKEN}/${PADDING_TOKEN}"
        }
    }

    open class KeyWrapping(
        override val algorithm: Algorithm,
        val blockMode: BlockMode,
        val digest: Digest,
        val padding: EncryptionPadding
    ) : Transformation {
        override val canonicalTransformation: String
            get() = CANONICAL_PATTERN
                .replace(ALGORITHM_TOKEN, algorithm.name)
                .replace(BLOCK_MODE_TOKEN, blockMode.name)
                .replace(PADDING_TOKEN, padding.name)

        override fun toString(): String {
            return "KeyWrapping(algorithm=$algorithm, blockMode=$blockMode, digest=$digest, padding=$padding, canonicalTransformation='$canonicalTransformation')"
        }

        protected companion object {
            const val ALGORITHM_TOKEN = "[ALGORITHM]"
            const val BLOCK_MODE_TOKEN = "[BLOCK_MODE]"
            const val PADDING_TOKEN = "[PADDING]"
            const val CANONICAL_PATTERN = "${ALGORITHM_TOKEN}/${BLOCK_MODE_TOKEN}/${PADDING_TOKEN}"
        }
    }
}
