package dev.kryptonreborn.ed25519

/**
 * Partial projective point representation ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
 *
 * Note that this is referred as complete form in the original ref10 impl (ge_p1p1).
 * Also note that t = T below following Java coding style.
 *
 * Although this has the same types as XYZT, it is redefined to have its own type so that it is
 * readable and 1:1 corresponds to ref10 impl.
 *
 * Can be converted to XYZT as follows:
 *
 * ```
 * X1 = X * T = x * Z * T = x * Z1
 * Y1 = Y * Z = y * T * Z = y * Z1
 * Z1 = Z * T = Z * T
 * T1 = X * Y = x * Z * y * T = x * y * Z1 = X1Y1 / Z1
 * ```
 */
class PartialXYZT {
    val xyz: XYZ
    val t: LongArray

    constructor(
        xyz: XYZ = XYZ(),
        t: LongArray = LongArray(Field25519.LIMB_CNT),
    ) {
        this.xyz = xyz
        this.t = t
    }

    constructor(other: PartialXYZT) {
        xyz = XYZ(other.xyz)
        t = other.t.copyOf(Field25519.LIMB_CNT)
    }
}
