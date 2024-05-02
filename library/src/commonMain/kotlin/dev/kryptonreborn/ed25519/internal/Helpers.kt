package dev.kryptonreborn.ed25519.internal

import dev.kryptonreborn.ed25519.Field25519

/**
 * Returns the least significant bit of [`in`].
 */
internal fun getLsb(inLongArray: LongArray): Int {
    return Field25519.contract(inLongArray)[0].toInt() and 1
}

/**
 * Computes [inLongArray]^(2^252-3) mod 2^255-19 and puts the result in [out].
 */
internal fun pow2252m3(out: LongArray, inLongArray: LongArray) {
    val t0 = LongArray(Field25519.LIMB_CNT)
    val t1 = LongArray(Field25519.LIMB_CNT)
    val t2 = LongArray(Field25519.LIMB_CNT)

    // z2 = z1^2^1
    Field25519.square(t0, inLongArray)

    // z8 = z2^2^2
    Field25519.square(t1, t0)
    for (i in 1..1) {
        Field25519.square(t1, t1)
    }

    // z9 = z1*z8
    Field25519.mult(t1, inLongArray, t1)

    // z11 = z2*z9
    Field25519.mult(t0, t0, t1)

    // z22 = z11^2^1
    Field25519.square(t0, t0)

    // z_5_0 = z9*z22
    Field25519.mult(t0, t1, t0)

    // z_10_5 = z_5_0^2^5
    Field25519.square(t1, t0)
    for (i in 1..4) {
        Field25519.square(t1, t1)
    }

    // z_10_0 = z_10_5*z_5_0
    Field25519.mult(t0, t1, t0)

    // z_20_10 = z_10_0^2^10
    Field25519.square(t1, t0)
    for (i in 1..9) {
        Field25519.square(t1, t1)
    }

    // z_20_0 = z_20_10*z_10_0
    Field25519.mult(t1, t1, t0)

    // z_40_20 = z_20_0^2^20
    Field25519.square(t2, t1)
    for (i in 1..19) {
        Field25519.square(t2, t2)
    }

    // z_40_0 = z_40_20*z_20_0
    Field25519.mult(t1, t2, t1)

    // z_50_10 = z_40_0^2^10
    Field25519.square(t1, t1)
    for (i in 1..9) {
        Field25519.square(t1, t1)
    }

    // z_50_0 = z_50_10*z_10_0
    Field25519.mult(t0, t1, t0)

    // z_100_50 = z_50_0^2^50
    Field25519.square(t1, t0)
    for (i in 1..49) {
        Field25519.square(t1, t1)
    }

    // z_100_0 = z_100_50*z_50_0
    Field25519.mult(t1, t1, t0)

    // z_200_100 = z_100_0^2^100
    Field25519.square(t2, t1)
    for (i in 1..99) {
        Field25519.square(t2, t2)
    }

    // z_200_0 = z_200_100*z_100_0
    Field25519.mult(t1, t2, t1)

    // z_250_50 = z_200_0^2^50
    Field25519.square(t1, t1)
    for (i in 1..49) {
        Field25519.square(t1, t1)
    }

    // z_250_0 = z_250_50*z_50_0
    Field25519.mult(t0, t1, t0)

    // z_252_2 = z_250_0^2^2
    Field25519.square(t0, t0)
    for (i in 1..1) {
        Field25519.square(t0, t0)
    }

    // z_252_3 = z_252_2*z1
    Field25519.mult(out, t0, inLongArray)
}

/**
 * Returns true if [in1] is nonzero.
 *
 * Note that execution time might depend on the input [in1].
 */
internal fun isNonZeroVarTime(in1: LongArray): Boolean {
    val inCopy = LongArray(in1.size + 1)
    in1.copyInto(inCopy, endIndex = in1.size)
    Field25519.reduceCoefficients(inCopy)
    val bytes = Field25519.contract(inCopy)
    for (b in bytes) {
        if (b.toInt() != 0) {
            return true
        }
    }
    return false
}

/**
 * Negates all values in [in1] and store it in [out].
 */
internal fun neg(out: LongArray, in1: LongArray) {
    for (i in in1.indices) {
        out[i] = -in1[i]
    }
}
