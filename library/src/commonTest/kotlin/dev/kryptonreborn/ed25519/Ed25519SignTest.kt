package dev.kryptonreborn.ed25519

import org.kotlincrypto.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.fail

@OptIn(ExperimentalStdlibApi::class)
class Ed25519SignTest {
    private val sRandom = SecureRandom()

    @Test
    fun testSigningOneKeyWithMultipleMessages() {
        val keyPair = generateKeyPairForTest()
        val signer = Ed25519Sign(keyPair.privateKey)
        val verifier = Ed25519Verify(keyPair.publicKey)
        for (i in 0..99) {
            val msg = randomByteArray(20)
            val sig = signer.sign(msg)
            if (!verifier.verify(sig, msg)) {
                fail(
                    """
          |Message: ${msg.toHexString()}
          |Signature: ${sig.toHexString()}
          |PrivateKey: ${keyPair.privateKey.toHexString()}
          |PublicKey: ${keyPair.publicKey.toHexString()}
                    """.trimMargin(),
                )
            }
        }
    }

    @Test
    fun testSigningOneKeyWithTheSameMessage() {
        val keyPair = generateKeyPairForTest()
        val signer = Ed25519Sign(keyPair.privateKey)
        val verifier = Ed25519Verify(keyPair.publicKey)
        val msg = randomByteArray(20)
        val allSignatures = mutableSetOf<String>()
        for (i in 0..99) {
            val sig = signer.sign(msg)
            allSignatures.add(sig.toHexString())
            if (!verifier.verify(sig, msg)) {
                fail(
                    """
          |Message: ${msg.toHexString()}
          |Signature: ${sig.toHexString()}
          |PrivateKey: ${keyPair.privateKey.toHexString()}
          |PublicKey: ${keyPair.publicKey.toHexString()}
                    """.trimMargin(),
                )
            }
        }
        // Ed25519 is deterministic, expect a unique signature for the same message.
        assertEquals(1, allSignatures.size.toLong())
    }

    @Test
    fun testSignWithPrivateKeyLengthDifferentFrom32Byte() {
        assertFailsWith<IllegalArgumentException> {
            Ed25519Sign(ByteArray(31))
        }
        assertFailsWith<IllegalArgumentException> {
            Ed25519Sign(ByteArray(33))
        }
    }

    @Test
    fun testSigningWithMultipleRandomKeysAndMessages() {
        for (i in 0..99) {
            val keyPair = generateKeyPairForTest()
            val signer = Ed25519Sign(keyPair.privateKey)
            val verifier = Ed25519Verify(keyPair.publicKey)
            val msg = randomByteArray(20)
            val sig = signer.sign(msg)
            if (!verifier.verify(sig, msg)) {
                fail(
                    """
          |Message: ${msg.toHexString()}
          |Signature: ${sig.toHexString()}
          |PrivateKey: ${keyPair.privateKey.toHexString()}
          |PublicKey: ${keyPair.publicKey.toHexString()}
                    """.trimMargin(),
                )
            }
        }
    }

    @Test
    fun testSigningWithWycheproofVectors() {
        val errors = 0
        val testGroups = loadEddsaTestJson().testGroups
        for (group in testGroups) {
            val key = group.key
            val privateKey = key.sk!!.hexToByteArray()
            val tests = group.tests
            for (testcase in tests) {
                val tcId = "testcase ${testcase.tcId} (${testcase.comment})"
                val msg = testcase.msg.hexToByteArray()
                val sig = testcase.sig
                val result = testcase.result
                if (result == "invalid") {
                    continue
                }
                val signer = Ed25519Sign(privateKey)
                val computedSig = signer.sign(msg).toHexString()
                assertEquals(sig, computedSig, tcId)
            }
        }
        assertEquals(0, errors.toLong())
    }

    @Test
    fun testKeyPairFromSeedTooShort() {
        val keyMaterial = randomByteArray(10)
        assertFailsWith<IllegalArgumentException> {
            newKeyPairFromSeed(keyMaterial)
        }
    }

    private fun randomByteArray(size: Int): ByteArray {
        return sRandom.nextBytesOf(size)
    }

    private fun generateKeyPairForTest(): KeyPair {
        return newKeyPairFromSeed(randomByteArray(Field25519.FIELD_LEN))
    }
}
