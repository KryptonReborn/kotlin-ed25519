package dev.kryptonreborn.ed25519

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@OptIn(ExperimentalStdlibApi::class)
class Ed25519VerifyTest {
    @Test
    fun testVerificationWithPublicKeyLengthDifferentFrom32Byte() {
        assertFailsWith<IllegalArgumentException> {
            Ed25519Verify(ByteArray(31))
        }
        assertFailsWith<IllegalArgumentException> {
            Ed25519Verify(ByteArray(33))
        }
    }

    @Test
    fun testVerificationWithWycheproofVectors() {
        var errors = 0
        val testGroups = loadEddsaTestJson().testGroups
        for (group in testGroups) {
            val key = group.key
            val publicKey = key.pk!!.hexToByteArray()
            val tests = group.tests
            for (testcase in tests) {
                val tcId = "testcase ${testcase.tcId} (${testcase.comment})"
                val msg = testcase.msg.hexToByteArray()
                val sig = testcase.sig.hexToByteArray()
                val result = testcase.result
                val verifier = Ed25519Verify(publicKey)
                if (verifier.verify(sig, msg)) {
                    if (result == "invalid") {
                        println("FAIL $tcId: accepting invalid signature")
                        errors++
                    }
                } else {
                    if (result == "valid") {
                        println("FAIL $tcId: rejecting valid signature")
                        errors++
                    }
                }
            }
        }
        assertEquals(0, errors.toLong())
    }
}
