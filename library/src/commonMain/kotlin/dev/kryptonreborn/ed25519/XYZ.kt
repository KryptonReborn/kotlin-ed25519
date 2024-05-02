package dev.kryptonreborn.ed25519

import dev.kryptonreborn.ed25519.internal.getLsb

/**
 * Projective point representation (X:Y:Z) satisfying x = X/Z, y = Y/Z
 *
 * Note that this is referred as ge_p2 in ref10 impl.
 * Also note that x = X, y = Y and z = Z below following Java coding style.
 *
 * See
 * Koyama K., Tsuruoka Y. (1993) Speeding up Elliptic Cryptosystems by Using a Signed Binary
 * Window Method.
 *
 * https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
 */
class XYZ {
    val x: LongArray
    val y: LongArray
    val z: LongArray

    constructor(
        x: LongArray = LongArray(Field25519.LIMB_CNT),
        y: LongArray = LongArray(Field25519.LIMB_CNT),
        z: LongArray = LongArray(Field25519.LIMB_CNT),
    ) {
        this.x = x
        this.y = y
        this.z = z
    }

    constructor(xyz: XYZ) {
        x = xyz.x.copyOf(Field25519.LIMB_CNT)
        y = xyz.y.copyOf(Field25519.LIMB_CNT)
        z = xyz.z.copyOf(Field25519.LIMB_CNT)
    }

    constructor(partialXYZT: PartialXYZT) : this() {
        fromPartialXYZT(this, partialXYZT)
    }

    /**
     * Encodes this point to bytes.
     */
    fun toBytes(): ByteArray {
        val recip = LongArray(Field25519.LIMB_CNT)
        val x = LongArray(Field25519.LIMB_CNT)
        val y = LongArray(Field25519.LIMB_CNT)
        Field25519.inverse(recip, z)
        Field25519.mult(x, this.x, recip)
        Field25519.mult(y, this.y, recip)
        val s = Field25519.contract(y)
        s[31] = (s[31].toInt() xor (getLsb(x) shl 7)).toByte()
        return s
    }

    /** Checks that the point is on curve  */
    fun isOnCurve(): Boolean {
        val x2 = LongArray(Field25519.LIMB_CNT)
        Field25519.square(x2, x)
        val y2 = LongArray(Field25519.LIMB_CNT)
        Field25519.square(y2, y)
        val z2 = LongArray(Field25519.LIMB_CNT)
        Field25519.square(z2, z)
        val z4 = LongArray(Field25519.LIMB_CNT)
        Field25519.square(z4, z2)
        val lhs = LongArray(Field25519.LIMB_CNT)
        // lhs = y^2 - x^2
        Field25519.sub(lhs, y2, x2)
        // lhs = z^2 * (y2 - x2)
        Field25519.mult(lhs, lhs, z2)
        val rhs = LongArray(Field25519.LIMB_CNT)
        // rhs = x^2 * y^2
        Field25519.mult(rhs, x2, y2)
        // rhs = D * x^2 * y^2
        Field25519.mult(rhs, rhs, Ed25519Constants.D)
        // rhs = z^4 + D * x^2 * y^2
        Field25519.sum(rhs, z4)
        // Field25519.mult reduces its output, but Field25519.sum does not, so we have to manually
        // reduce it here.
        Field25519.reduce(rhs, rhs)
        // z^2 (y^2 - x^2) == z^4 + D * x^2 * y^2
        return fixedTimingEqual(Field25519.contract(lhs), Field25519.contract(rhs))
    }

    companion object {
        /**
         * Best effort fix-timing array comparison.
         *
         * @return true if two arrays are equal.
         */
        fun fixedTimingEqual(x: ByteArray, y: ByteArray): Boolean {
            if (x.size != y.size) {
                return false
            }
            var res = 0
            for (i in x.indices) {
                res = res or (x[i].toInt() xor y[i].toInt())
            }
            return res == 0
        }

        /**
         * ge_p1p1_to_p2.c
         */
        fun fromPartialXYZT(out: XYZ, inXyzt: PartialXYZT): XYZ {
            Field25519.mult(out.x, inXyzt.xyz.x, inXyzt.t)
            Field25519.mult(out.y, inXyzt.xyz.y, inXyzt.xyz.z)
            Field25519.mult(out.z, inXyzt.xyz.z, inXyzt.t)
            return out
        }
    }
}