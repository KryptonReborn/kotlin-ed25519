package dev.kryptonreborn.ed25519

import dev.kryptonreborn.ed25519.Ed25519.verify

/**
 * Ed25519 verifying.
 *
 * # Usage
 *
 * ```
 * // get the publicKey from the other party.
 * val verifier = new Ed25519Verify(publicKey)
 * if (!verifier.verify(signature, message)) {
 *   // Signature didn't verify.
 * }
 * ```
 *
 * @since 1.1.0
 */
internal class Ed25519Verify(
    private val publicKey: ByteArray,
) {
    init {
        require(publicKey.size == PUBLIC_KEY_LEN) {
            "Given public key's length is not $PUBLIC_KEY_LEN."
        }
    }

    fun verify(signature: ByteArray, data: ByteArray): Boolean {
        if (signature.size != SIGNATURE_LEN) {
            return false
        }
        return verify(data, signature, publicKey)
    }

    companion object {
        const val PUBLIC_KEY_LEN = Field25519.FIELD_LEN
        const val SIGNATURE_LEN = Field25519.FIELD_LEN * 2
    }
}
