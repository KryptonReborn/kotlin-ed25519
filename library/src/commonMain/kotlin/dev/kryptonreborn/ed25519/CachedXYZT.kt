package dev.kryptonreborn.ed25519

/**
 * Creates a cached XYZT
 *
 * @param yPlusX Y + X
 * @param yMinusX Y - X
 * @param z Z
 * @param t2d 2d * (XY/Z)
 */
class CachedXYZT(
    yPlusX: LongArray = LongArray(Field25519.LIMB_CNT),
    yMinusX: LongArray = LongArray(Field25519.LIMB_CNT),
    private val z: LongArray = LongArray(Field25519.LIMB_CNT),
    t2d: LongArray = LongArray(Field25519.LIMB_CNT),
) : CachedXYT(yPlusX, yMinusX, t2d) {

    /**
     * ge_p3_to_cached.c
     */
    constructor(xyzt: XYZT) : this() {
        Field25519.sum(yPlusX, xyzt.xyz.y, xyzt.xyz.x)
        Field25519.sub(yMinusX, xyzt.xyz.y, xyzt.xyz.x)
        xyzt.xyz.z.copyInto(z, endIndex = Field25519.LIMB_CNT)
        Field25519.mult(t2d, xyzt.t, Ed25519Constants.D2)
    }

    override fun multByZ(output: LongArray, inLongArray: LongArray) {
        Field25519.mult(output, inLongArray, z)
    }
}
