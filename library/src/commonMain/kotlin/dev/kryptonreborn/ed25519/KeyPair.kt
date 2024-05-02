package dev.kryptonreborn.ed25519

/**
 * Defines the KeyPair consisting of a private key and its corresponding public key.
 * */
data class KeyPair internal constructor(
    val publicKey: ByteArray,
    val privateKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KeyPair

        if (!publicKey.contentEquals(other.publicKey)) return false
        if (!privateKey.contentEquals(other.privateKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + privateKey.contentHashCode()
        return result
    }
}

/**
 * Returns a new `<publicKey / privateKey>` KeyPair generated from a seed.
 * */
fun newKeyPairFromSeed(secretSeed: ByteArray): KeyPair {
    require(secretSeed.size == Field25519.FIELD_LEN) {
        "Given secret seed length is not ${Field25519.FIELD_LEN}"
    }
    val publicKey = Ed25519.scalarMultWithBaseToBytes(Ed25519.getHashedScalar(secretSeed))
    return KeyPair(publicKey, secretSeed)
}
