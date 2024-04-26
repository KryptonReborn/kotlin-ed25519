package dev.kryptonreborn.ed25519

import dev.kryptonreborn.ed25519.Ed25519.getHashedScalar
import dev.kryptonreborn.ed25519.Ed25519.scalarMultWithBaseToBytes
import dev.kryptonreborn.ed25519.Ed25519.sign

/**
 * Ed25519 signing.
 *
 * # Usage
 *
 * ```
 * val keyPair = Ed25519Sign.KeyPair.newKeyPair()
 *
 * // securely store keyPair and share keyPair.getPublicKey()
 * val signer = Ed25519Sign(keyPair.getPrivateKey())
 * val signature = signer.sign(message)
 * ```
 *
 * @since 1.1.0
 */
internal class Ed25519Sign private constructor(
    private val hashedPrivateKey: ByteArray,
    private val publicKey: ByteArray,
) {
    fun sign(data: ByteArray): ByteArray {
        return sign(data, publicKey, hashedPrivateKey)
    }

    companion object {
        private const val SECRET_KEY_LEN = Field25519.FIELD_LEN

        /**
         * @param privateKey 32-byte random sequence.
         */
        operator fun invoke(privateKey: ByteArray): Ed25519Sign {
            require(privateKey.size == SECRET_KEY_LEN) {
                "Given private key's length is not $SECRET_KEY_LEN"
            }
            val hashedPrivateKey = getHashedScalar(privateKey)
            val publicKey = scalarMultWithBaseToBytes(hashedPrivateKey)
            return Ed25519Sign(hashedPrivateKey, publicKey)
        }
    }
}
