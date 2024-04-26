package dev.kryptonreborn.ed25519

import dev.kryptonreborn.ed25519.Curve25519.copyConditional

/**
 * Corresponds to the caching mentioned in the last paragraph of Section 3.1 of
 * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
 * with Z = 1.
 */
open class CachedXYT {
    val yPlusX: LongArray
    val yMinusX: LongArray
    val t2d: LongArray

    /**
     * Creates a cached XYZT with Z = 1
     *
     * @param yPlusX y + x
     * @param yMinusX y - x
     * @param t2d 2d * xy
     */
    constructor(yPlusX: LongArray, yMinusX: LongArray, t2d: LongArray) {
        this.yPlusX = yPlusX
        this.yMinusX = yMinusX
        this.t2d = t2d
    }

    constructor(other: CachedXYT) {
        yPlusX = other.yPlusX.copyOf(Field25519.LIMB_CNT)
        yMinusX = other.yMinusX.copyOf(Field25519.LIMB_CNT)
        t2d = other.t2d.copyOf(Field25519.LIMB_CNT)
    }

    // z is one implicitly, so this just copies {@code in} to {@code output}.
    open fun multByZ(output: LongArray, inLongArray: LongArray) {
        inLongArray.copyInto(output, endIndex = Field25519.LIMB_CNT)
    }

    /**
     * If icopy is 1, copies [other] into this point. Time invariant wrt to icopy value.
     */
    fun copyConditional(other: CachedXYT, icopy: Int) {
        copyConditional(yPlusX, other.yPlusX, icopy)
        copyConditional(yMinusX, other.yMinusX, icopy)
        copyConditional(t2d, other.t2d, icopy)
    }
}