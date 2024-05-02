package dev.kryptonreborn.ed25519

import dev.kryptonreborn.ed25519.internal.getLsb
import dev.kryptonreborn.ed25519.internal.isNonZeroVarTime
import dev.kryptonreborn.ed25519.internal.neg
import dev.kryptonreborn.ed25519.internal.pow2252m3

/**
 * Represents extended projective point representation (X:Y:Z:T) satisfying x = X/Z, y = Y/Z,
 * XY = ZT
 *
 * Note that this is referred as ge_p3 in ref10 impl.
 * Also note that t = T below following Java coding style.
 *
 * See
 * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
 *
 * https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html
 */
class XYZT(
    val xyz: XYZ = XYZ(),
    val t: LongArray = LongArray(Field25519.LIMB_CNT),
) {
    constructor(partialXYZT: PartialXYZT) : this() {
        fromPartialXYZT(this, partialXYZT)
    }

    companion object {
        /**
         * ge_p1p1_to_p2.c
         */
        fun fromPartialXYZT(out: XYZT, `in`: PartialXYZT): XYZT {
            Field25519.mult(out.xyz.x, `in`.xyz.x, `in`.t)
            Field25519.mult(out.xyz.y, `in`.xyz.y, `in`.xyz.z)
            Field25519.mult(out.xyz.z, `in`.xyz.z, `in`.t)
            Field25519.mult(out.t, `in`.xyz.x, `in`.xyz.y)
            return out
        }

        /**
         * Decodes `s` into an extented projective point.
         * See Section 5.1.3 Decoding in https://tools.ietf.org/html/rfc8032#section-5.1.3
         */
        fun fromBytesNegateVarTime(s: ByteArray): XYZT {
            val x = LongArray(Field25519.LIMB_CNT)
            val y = Field25519.expand(s)
            val z = LongArray(Field25519.LIMB_CNT)
            z[0] = 1
            val t = LongArray(Field25519.LIMB_CNT)
            val u = LongArray(Field25519.LIMB_CNT)
            val v = LongArray(Field25519.LIMB_CNT)
            val vxx = LongArray(Field25519.LIMB_CNT)
            val check = LongArray(Field25519.LIMB_CNT)
            Field25519.square(u, y)
            Field25519.mult(v, u, Ed25519Constants.D)
            Field25519.sub(u, u, z) // u = y^2 - 1
            Field25519.sum(v, v, z) // v = dy^2 + 1

            val v3 = LongArray(Field25519.LIMB_CNT)
            Field25519.square(v3, v)
            Field25519.mult(v3, v3, v) // v3 = v^3
            Field25519.square(x, v3)
            Field25519.mult(x, x, v)
            Field25519.mult(x, x, u) // x = uv^7

            pow2252m3(x, x) // x = (uv^7)^((q-5)/8)
            Field25519.mult(x, x, v3)
            Field25519.mult(x, x, u) // x = uv^3(uv^7)^((q-5)/8)

            Field25519.square(vxx, x)
            Field25519.mult(vxx, vxx, v)
            Field25519.sub(check, vxx, u) // vx^2-u
            if (isNonZeroVarTime(check)) {
                Field25519.sum(check, vxx, u) // vx^2+u
                check(!isNonZeroVarTime(check)) {
                    "Cannot convert given bytes to extended projective " +
                            "coordinates. No square root exists for modulo 2^255-19"
                }
                Field25519.mult(x, x, Ed25519Constants.SQRTM1)
            }

            check(isNonZeroVarTime(x) || s[31].toInt() and 0xff shr 7 == 0) {
                "Cannot convert given bytes to extended projective " +
                        "coordinates. Computed x is zero and encoded x's least significant bit is not zero"
            }
            if (getLsb(x) == s[31].toInt() and 0xff shr 7) {
                neg(x, x)
            }

            Field25519.mult(t, x, y)
            return XYZT(XYZ(x, y, z), t)
        }
    }
}
