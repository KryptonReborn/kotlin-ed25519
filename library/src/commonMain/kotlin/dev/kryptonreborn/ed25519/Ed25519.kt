package dev.kryptonreborn.ed25519

import dev.kryptonreborn.ed25519.internal.neg
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import org.kotlincrypto.hash.sha2.SHA512

/**
 * Based on the implementation from Zipline
 *
 * This implementation is based on the ed25519/ref10 implementation in NaCl.
 *
 * It implements this twisted Edwards curve:
 *
 * ```
 * -x^2 + y^2 = 1 + (-121665 / 121666 mod 2^255-19)*x^2*y^2
 * ```
 *
 * @see [Bernstein D.J., Birkner P., Joye M., Lange T., Peters C. (2008) Twisted Edwards
 *     Curves](https://eprint.iacr.org/2008/013.pdf)
 * @see [Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves
 *     Revisited](https://eprint.iacr.org/2008/522.pdf)
 * @see [Zipline](https://github.com/cashapp/zipline/blob/trunk/zipline-loader/src/commonMain/kotlin/app/cash/zipline/loader/internal/tink/subtle/Ed25519.kt)
 */
object Ed25519 {
    private const val SIGNATURE_LEN = Field25519.FIELD_LEN * 2

    // (x = 0, y = 1) point
    private val CACHED_NEUTRAL = CachedXYT(
        longArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        longArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        longArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )
    private val NEUTRAL = PartialXYZT(
        XYZ(
            longArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            longArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            longArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        ),
        longArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )

    // The order of the generator as unsigned bytes in little endian order.
    // (2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed, cf. RFC 7748)
    private val GROUP_ORDER = byteArrayOf(
        0xed.toByte(), 0xd3.toByte(), 0xf5.toByte(), 0x5c.toByte(),
        0x1a.toByte(), 0x63.toByte(), 0x12.toByte(), 0x58.toByte(),
        0xd6.toByte(), 0x9c.toByte(), 0xf7.toByte(), 0xa2.toByte(),
        0xde.toByte(), 0xf9.toByte(), 0xde.toByte(), 0x14.toByte(),
        0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x10.toByte(),
    )

    /**
     * Addition defined in Section 3.1 of
     * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
     *
     * Please note that this is a partial of the operation listed there leaving out the final
     * conversion from PartialXYZT to XYZT.
     *
     * @param extended extended projective point input
     * @param cached cached projective point input
     */
    private fun add(partialXYZT: PartialXYZT, extended: XYZT, cached: CachedXYT?) {
        val t = LongArray(Field25519.LIMB_CNT)

        // Y1 + X1
        Field25519.sum(partialXYZT.xyz.x, extended.xyz.y, extended.xyz.x)

        // Y1 - X1
        Field25519.sub(partialXYZT.xyz.y, extended.xyz.y, extended.xyz.x)

        // A = (Y1 - X1) * (Y2 - X2)
        Field25519.mult(partialXYZT.xyz.y, partialXYZT.xyz.y, cached!!.yMinusX)

        // B = (Y1 + X1) * (Y2 + X2)
        Field25519.mult(partialXYZT.xyz.z, partialXYZT.xyz.x, cached.yPlusX)

        // C = T1 * 2d * T2 = 2d * T1 * T2 (2d is written as k in the paper)
        Field25519.mult(partialXYZT.t, extended.t, cached.t2d)

        // Z1 * Z2
        cached.multByZ(partialXYZT.xyz.x, extended.xyz.z)

        // D = 2 * Z1 * Z2
        Field25519.sum(t, partialXYZT.xyz.x, partialXYZT.xyz.x)

        // X3 = B - A
        Field25519.sub(partialXYZT.xyz.x, partialXYZT.xyz.z, partialXYZT.xyz.y)

        // Y3 = B + A
        Field25519.sum(partialXYZT.xyz.y, partialXYZT.xyz.z, partialXYZT.xyz.y)

        // Z3 = D + C
        Field25519.sum(partialXYZT.xyz.z, t, partialXYZT.t)

        // T3 = D - C
        Field25519.sub(partialXYZT.t, t, partialXYZT.t)
    }

    /**
     * Based on the addition defined in Section 3.1 of
     * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
     *
     * Please note that this is a partial of the operation listed there leaving out the final
     * conversion from PartialXYZT to XYZT.
     *
     * @param extended extended projective point input
     * @param cached cached projective point input
     */
    private fun sub(
        partialXYZT: PartialXYZT,
        extended: XYZT,
        cached: CachedXYT?,
    ) {
        val t = LongArray(Field25519.LIMB_CNT)

        // Y1 + X1
        Field25519.sum(partialXYZT.xyz.x, extended.xyz.y, extended.xyz.x)

        // Y1 - X1
        Field25519.sub(partialXYZT.xyz.y, extended.xyz.y, extended.xyz.x)

        // A = (Y1 - X1) * (Y2 + X2)
        Field25519.mult(partialXYZT.xyz.y, partialXYZT.xyz.y, cached!!.yPlusX)

        // B = (Y1 + X1) * (Y2 - X2)
        Field25519.mult(partialXYZT.xyz.z, partialXYZT.xyz.x, cached.yMinusX)

        // C = T1 * 2d * T2 = 2d * T1 * T2 (2d is written as k in the paper)
        Field25519.mult(partialXYZT.t, extended.t, cached.t2d)

        // Z1 * Z2
        cached.multByZ(partialXYZT.xyz.x, extended.xyz.z)

        // D = 2 * Z1 * Z2
        Field25519.sum(t, partialXYZT.xyz.x, partialXYZT.xyz.x)

        // X3 = B - A
        Field25519.sub(partialXYZT.xyz.x, partialXYZT.xyz.z, partialXYZT.xyz.y)

        // Y3 = B + A
        Field25519.sum(partialXYZT.xyz.y, partialXYZT.xyz.z, partialXYZT.xyz.y)

        // Z3 = D - C
        Field25519.sub(partialXYZT.xyz.z, t, partialXYZT.t)

        // T3 = D + C
        Field25519.sum(partialXYZT.t, t, partialXYZT.t)
    }

    /**
     * Doubles [p] and puts the result into this PartialXYZT.
     *
     * This is based on the addition defined in formula 7 in Section 3.3 of
     * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
     *
     * Please note that this is a partial of the operation listed there leaving out the final
     * conversion from PartialXYZT to XYZT and also this fixes a typo in calculation of Y3 and T3 in
     * the paper, H should be replaced with A+B.
     */
    private fun doubleXYZ(partialXYZT: PartialXYZT, p: XYZ) {
        val t0 = LongArray(Field25519.LIMB_CNT)

        // XX = X1^2
        Field25519.square(partialXYZT.xyz.x, p.x)

        // YY = Y1^2
        Field25519.square(partialXYZT.xyz.z, p.y)

        // B' = Z1^2
        Field25519.square(partialXYZT.t, p.z)

        // B = 2 * B'
        Field25519.sum(partialXYZT.t, partialXYZT.t, partialXYZT.t)

        // A = X1 + Y1
        Field25519.sum(partialXYZT.xyz.y, p.x, p.y)

        // AA = A^2
        Field25519.square(t0, partialXYZT.xyz.y)

        // Y3 = YY + XX
        Field25519.sum(partialXYZT.xyz.y, partialXYZT.xyz.z, partialXYZT.xyz.x)

        // Z3 = YY - XX
        Field25519.sub(partialXYZT.xyz.z, partialXYZT.xyz.z, partialXYZT.xyz.x)

        // X3 = AA - Y3
        Field25519.sub(partialXYZT.xyz.x, t0, partialXYZT.xyz.y)

        // T3 = B - Z3
        Field25519.sub(partialXYZT.t, partialXYZT.t, partialXYZT.xyz.z)
    }

    /**
     * Doubles [p] and puts the result into this PartialXYZT.
     */
    private fun doubleXYZT(
        partialXYZT: PartialXYZT,
        p: XYZT,
    ) {
        doubleXYZ(partialXYZT, p.xyz)
    }

    /**
     * Compares two byte values in constant time.
     *
     * Please note that this doesn't reuse [Curve25519#eq] method since the below inputs are
     * byte values.
     */
    private fun eq(a: Int, b: Int): Int {
        var r = (a xor b).inv() and 0xff
        r = r and (r shl 4)
        r = r and (r shl 2)
        r = r and (r shl 1)
        return r shr 7 and 1
    }

    /**
     * This is a constant time operation where point b*B*256^pos is stored in [t].
     * When b is 0, t remains the same (i.e., neutral point).
     *
     * Although `B_TABLE[32][8] (B_TABLE[i][j] = (j+1)*B*256^i)` has j values in `[0, 7]`, the select
     * method negates the corresponding point if b is negative (which is straight forward in elliptic
     * curves by just negating y coordinate). Therefore, we can get multiples of B with the half of
     * memory requirements.
     *
     * @param t neutral element (i.e., point 0), also serves as output.
     * @param pos in `B[pos][j] = (j+1)*B*256^pos`
     * @param b value in `[-8, 8]` range.
     */
    private fun select(t: CachedXYT, pos: Int, b: Byte) {
        val bnegative = b.toInt() and 0xff shr 7
        val babs = b - (-bnegative and b.toInt() shl 1)
        t.copyConditional(Ed25519Constants.B_TABLE[pos][0], eq(babs, 1))
        t.copyConditional(Ed25519Constants.B_TABLE[pos][1], eq(babs, 2))
        t.copyConditional(Ed25519Constants.B_TABLE[pos][2], eq(babs, 3))
        t.copyConditional(Ed25519Constants.B_TABLE[pos][3], eq(babs, 4))
        t.copyConditional(Ed25519Constants.B_TABLE[pos][4], eq(babs, 5))
        t.copyConditional(Ed25519Constants.B_TABLE[pos][5], eq(babs, 6))
        t.copyConditional(Ed25519Constants.B_TABLE[pos][6], eq(babs, 7))
        t.copyConditional(Ed25519Constants.B_TABLE[pos][7], eq(babs, 8))
        val yPlusX = t.yMinusX.copyOf(Field25519.LIMB_CNT)
        val yMinusX = t.yPlusX.copyOf(Field25519.LIMB_CNT)
        val t2d = t.t2d.copyOf(Field25519.LIMB_CNT)
        neg(t2d, t2d)
        val minust = CachedXYT(yPlusX, yMinusX, t2d)
        t.copyConditional(minust, bnegative)
    }

    /**
     * Computes [a]*B
     * where `a = a[0]+256*a[1]+...+256^31 a[31]` and
     * B is the Ed25519 base point (x,4/5) with x positive.
     *
     * Preconditions:
     * `a[31] <= 127`
     * @throws IllegalStateException iff there is arithmetic error.
     */
    private fun scalarMultWithBase(a: ByteArray): XYZ {
        val e = ByteArray(2 * Field25519.FIELD_LEN)
        for (i in 0 until Field25519.FIELD_LEN) {
            e[2 * i + 0] = (a[i].toInt() and 0xff shr 0 and 0xf).toByte()
            e[2 * i + 1] = (a[i].toInt() and 0xff shr 4 and 0xf).toByte()
        }
        // each e[i] is between 0 and 15
        // e[63] is between 0 and 7

        // Rewrite e in a way that each e[i] is in [-8, 8].
        // This can be done since a[63] is in [0, 7], the carry-over onto the most significant byte
        // a[63] can be at most 1.
        var carry = 0
        for (i in 0 until e.size - 1) {
            e[i] = (e[i] + carry).toByte()
            carry = e[i] + 8
            carry = carry shr 4
            e[i] = (e[i] - (carry shl 4)).toByte()
        }
        e[e.size - 1] = (e[e.size - 1] + carry).toByte()

        val ret = PartialXYZT(NEUTRAL)
        val xyzt = XYZT()
        // Although B_TABLE's i can be at most 31 (stores only 32 4bit multiples of B) and we have 64
        // 4bit values in e array, the below for loop adds cached values by iterating e by two in odd
        // indices. After the result, we can double the result point 4 times to shift the multiplication
        // scalar by 4 bits.
        run {
            var i = 1
            while (i < e.size) {
                val t = CachedXYT(CACHED_NEUTRAL)
                select(t, i / 2, e[i])
                add(ret, XYZT.fromPartialXYZT(xyzt, ret), t)
                i += 2
            }
        }

        // Doubles the result 4 times to shift the multiplication scalar 4 bits to get the actual result
        // for the odd indices in e.
        val xyz = XYZ()
        doubleXYZ(ret, XYZ.fromPartialXYZT(xyz, ret))
        doubleXYZ(ret, XYZ.fromPartialXYZT(xyz, ret))
        doubleXYZ(ret, XYZ.fromPartialXYZT(xyz, ret))
        doubleXYZ(ret, XYZ.fromPartialXYZT(xyz, ret))

        // Add multiples of B for even indices of e.
        var i = 0
        while (i < e.size) {
            val t = CachedXYT(CACHED_NEUTRAL)
            select(t, i / 2, e[i])
            add(ret, XYZT.fromPartialXYZT(xyzt, ret), t)
            i += 2
        }

        // This check is to protect against flaws, i.e. if there is a computation error through a
        // faulty CPU or if the implementation contains a bug.
        val result = XYZ(ret)
        check(result.isOnCurve()) { "arithmetic error in scalar multiplication" }
        return result
    }

    /**
     * Computes [a]*B
     * where `a = a[0]+256*a[1]+...+256^31 a[31]` and
     * B is the Ed25519 base point (x,4/5) with x positive.
     *
     * Preconditions:
     * `a[31] <= 127`
     */
    fun scalarMultWithBaseToBytes(a: ByteArray): ByteArray {
        return scalarMultWithBase(a).toBytes()
    }

    private fun slide(a: ByteArray): ByteArray {
        val r = ByteArray(256)
        // Writes each bit in a[0..31] into r[0..255]:
        // a = a[0]+256*a[1]+...+256^31*a[31] is equal to
        // r = r[0]+2*r[1]+...+2^255*r[255]
        for (i in 0..255) {
            r[i] = (1 and (a[i shr 3].toInt() and 0xff shr (i and 7))).toByte()
        }

        // Transforms r[i] as odd values in [-15, 15]
        for (i in 0..255) {
            if (r[i].toInt() != 0) {
                var b = 1
                while (b <= 6 && i + b < 256) {
                    if (r[i + b].toInt() != 0) {
                        if (r[i] + (r[i + b].toInt() shl b) <= 15) {
                            r[i] = (r[i] + (r[i + b].toInt() shl b)).toByte()
                            r[i + b] = 0
                        } else if (r[i] - (r[i + b].toInt() shl b) >= -15) {
                            r[i] = (r[i] - (r[i + b].toInt() shl b)).toByte()
                            for (k in i + b..255) {
                                if (r[k].toInt() == 0) {
                                    r[k] = 1
                                    break
                                }
                                r[k] = 0
                            }
                        } else {
                            break
                        }
                    }
                    b++
                }
            }
        }
        return r
    }

    /**
     * Computes [a]*[pointA]+[b]*B
     * where `a = a[0]+256*a[1]+...+256^31*a[31]`.
     * and `b = b[0]+256*b[1]+...+256^31*b[31]`.
     * B is the Ed25519 base point (x,4/5) with x positive.
     *
     * Note that execution time varies based on the input since this will only be used in verification
     * of signatures.
     */
    private fun doubleScalarMultVarTime(a: ByteArray, pointA: XYZT, b: ByteArray): XYZ {
        // pointA, 3*pointA, 5*pointA, 7*pointA, 9*pointA, 11*pointA, 13*pointA, 15*pointA
        val pointAArray = arrayOfNulls<CachedXYZT>(8)
        pointAArray[0] = CachedXYZT(pointA)
        var t = PartialXYZT()
        doubleXYZT(t, pointA)
        val doubleA = XYZT(t)
        for (i in 1 until pointAArray.size) {
            add(t, doubleA, pointAArray[i - 1])
            pointAArray[i] = CachedXYZT(XYZT(t))
        }

        val aSlide = slide(a)
        val bSlide = slide(b)
        t = PartialXYZT(NEUTRAL)
        val u = XYZT()
        var i = 255
        while (i >= 0) {
            if (aSlide[i].toInt() != 0 || bSlide[i].toInt() != 0) {
                break
            }
            i--
        }
        while (i >= 0) {
            doubleXYZ(t, XYZ(t))
            if (aSlide[i] > 0) {
                add(t, XYZT.fromPartialXYZT(u, t), pointAArray[aSlide[i] / 2])
            } else if (aSlide[i] < 0) {
                sub(t, XYZT.fromPartialXYZT(u, t), pointAArray[-aSlide[i] / 2])
            }
            if (bSlide[i] > 0) {
                add(t, XYZT.fromPartialXYZT(u, t), Ed25519Constants.B2[bSlide[i] / 2])
            } else if (bSlide[i] < 0) {
                sub(t, XYZT.fromPartialXYZT(u, t), Ed25519Constants.B2[-bSlide[i] / 2])
            }
            i--
        }

        return XYZ(t)
    }

    /**
     * Returns 3 bytes of [inByteArray] starting from [idx] in Little-Endian format.
     */
    private fun load3(inByteArray: ByteArray, idx: Int): Long {
        var result: Long
        result = inByteArray[idx].toLong() and 0xffL
        result = result or ((inByteArray[idx + 1].toInt() and 0xff).toLong() shl 8)
        result = result or ((inByteArray[idx + 2].toInt() and 0xff).toLong() shl 16)
        return result
    }

    /**
     * Returns 4 bytes of [inByteArray] starting from [idx] in Little-Endian format.
     */
    private fun load4(inByteArray: ByteArray, idx: Int): Long {
        var result = load3(inByteArray, idx)
        result = result or ((inByteArray[idx + 3].toInt() and 0xff).toLong() shl 24)
        return result
    }

    /**
     * Input:
     * s[0]+256*s[1]+...+256^63*s[63] = s
     *
     * Output:
     * s[0]+256*s[1]+...+256^31*s[31] = s mod l
     * where l = 2^252 + 27742317777372353535851937790883648493.
     * Overwrites s in place.
     */
    private fun reduce(s: ByteArray) {
        // Observation:
        // 2^252 mod l is equivalent to -27742317777372353535851937790883648493 mod l
        // Let m = -27742317777372353535851937790883648493
        // Thus a*2^252+b mod l is equivalent to a*m+b mod l
        //
        // First s is divided into chunks of 21 bits as follows:
        // s0+2^21*s1+2^42*s3+...+2^462*s23 = s[0]+256*s[1]+...+256^63*s[63]
        var s0 = 2097151L and load3(s, 0)
        var s1 = 2097151L and (load4(s, 2) shr 5)
        var s2 = 2097151L and (load3(s, 5) shr 2)
        var s3 = 2097151L and (load4(s, 7) shr 7)
        var s4 = 2097151L and (load4(s, 10) shr 4)
        var s5 = 2097151L and (load3(s, 13) shr 1)
        var s6 = 2097151L and (load4(s, 15) shr 6)
        var s7 = 2097151L and (load3(s, 18) shr 3)
        var s8 = 2097151L and load3(s, 21)
        var s9 = 2097151L and (load4(s, 23) shr 5)
        var s10 = 2097151L and (load3(s, 26) shr 2)
        var s11 = 2097151L and (load4(s, 28) shr 7)
        var s12 = 2097151L and (load4(s, 31) shr 4)
        var s13 = 2097151L and (load3(s, 34) shr 1)
        var s14 = 2097151L and (load4(s, 36) shr 6)
        var s15 = 2097151L and (load3(s, 39) shr 3)
        var s16 = 2097151L and load3(s, 42)
        var s17 = 2097151L and (load4(s, 44) shr 5)
        val s18 = 2097151L and (load3(s, 47) shr 2)
        val s19 = 2097151L and (load4(s, 49) shr 7)
        val s20 = 2097151L and (load4(s, 52) shr 4)
        val s21 = 2097151L and (load3(s, 55) shr 1)
        val s22 = 2097151L and (load4(s, 57) shr 6)
        val s23 = load4(s, 60) shr 3

        // s23*2^462 = s23*2^210*2^252 is equivalent to s23*2^210*m in mod l
        // As m is a 125 bit number, the result needs to scattered to 6 limbs (125/21 ceil is 6)
        // starting from s11 (s11*2^210)
        // m = [666643, 470296, 654183, -997805, 136657, -683901] in 21-bit limbs
        s11 += s23 * 666643
        s12 += s23 * 470296
        s13 += s23 * 654183
        s14 -= s23 * 997805
        s15 += s23 * 136657
        s16 -= s23 * 683901
        // s23 = 0;

        s10 += s22 * 666643
        s11 += s22 * 470296
        s12 += s22 * 654183
        s13 -= s22 * 997805
        s14 += s22 * 136657
        s15 -= s22 * 683901
        // s22 = 0;

        s9 += s21 * 666643
        s10 += s21 * 470296
        s11 += s21 * 654183
        s12 -= s21 * 997805
        s13 += s21 * 136657
        s14 -= s21 * 683901
        // s21 = 0;

        s8 += s20 * 666643
        s9 += s20 * 470296
        s10 += s20 * 654183
        s11 -= s20 * 997805
        s12 += s20 * 136657
        s13 -= s20 * 683901
        // s20 = 0;

        s7 += s19 * 666643
        s8 += s19 * 470296
        s9 += s19 * 654183
        s10 -= s19 * 997805
        s11 += s19 * 136657
        s12 -= s19 * 683901
        // s19 = 0;

        s6 += s18 * 666643
        s7 += s18 * 470296
        s8 += s18 * 654183
        s9 -= s18 * 997805
        s10 += s18 * 136657
        s11 -= s18 * 683901
        // s18 = 0;

        // Reduce the bit length of limbs from s6 to s15 to 21-bits.
        var carry6: Long = s6 + (1 shl 20) shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        var carry8: Long = s8 + (1 shl 20) shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        var carry10: Long = s10 + (1 shl 20) shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        val carry12: Long = s12 + (1 shl 20) shr 21
        s13 += carry12
        s12 -= carry12 shl 21
        val carry14: Long = s14 + (1 shl 20) shr 21
        s15 += carry14
        s14 -= carry14 shl 21
        val carry16: Long = s16 + (1 shl 20) shr 21
        s17 += carry16
        s16 -= carry16 shl 21

        var carry7: Long = s7 + (1 shl 20) shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        var carry9: Long = s9 + (1 shl 20) shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        var carry11: Long = s11 + (1 shl 20) shr 21
        s12 += carry11
        s11 -= carry11 shl 21
        val carry13: Long = s13 + (1 shl 20) shr 21
        s14 += carry13
        s13 -= carry13 shl 21
        val carry15: Long = s15 + (1 shl 20) shr 21
        s16 += carry15
        s15 -= carry15 shl 21

        // Resume reduction where we left off.
        s5 += s17 * 666643
        s6 += s17 * 470296
        s7 += s17 * 654183
        s8 -= s17 * 997805
        s9 += s17 * 136657
        s10 -= s17 * 683901
        // s17 = 0;

        s4 += s16 * 666643
        s5 += s16 * 470296
        s6 += s16 * 654183
        s7 -= s16 * 997805
        s8 += s16 * 136657
        s9 -= s16 * 683901
        // s16 = 0;

        s3 += s15 * 666643
        s4 += s15 * 470296
        s5 += s15 * 654183
        s6 -= s15 * 997805
        s7 += s15 * 136657
        s8 -= s15 * 683901
        // s15 = 0;

        s2 += s14 * 666643
        s3 += s14 * 470296
        s4 += s14 * 654183
        s5 -= s14 * 997805
        s6 += s14 * 136657
        s7 -= s14 * 683901
        // s14 = 0;

        s1 += s13 * 666643
        s2 += s13 * 470296
        s3 += s13 * 654183
        s4 -= s13 * 997805
        s5 += s13 * 136657
        s6 -= s13 * 683901
        // s13 = 0;

        s0 += s12 * 666643
        s1 += s12 * 470296
        s2 += s12 * 654183
        s3 -= s12 * 997805
        s4 += s12 * 136657
        s5 -= s12 * 683901
        s12 = 0

        // Reduce the range of limbs from s0 to s11 to 21-bits.
        var carry0: Long = s0 + (1 shl 20) shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        var carry2: Long = s2 + (1 shl 20) shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        var carry4: Long = s4 + (1 shl 20) shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry6 = s6 + (1 shl 20) shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry8 = s8 + (1 shl 20) shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry10 = s10 + (1 shl 20) shr 21
        s11 += carry10
        s10 -= carry10 shl 21

        var carry1: Long = s1 + (1 shl 20) shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        var carry3: Long = s3 + (1 shl 20) shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        var carry5: Long = s5 + (1 shl 20) shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry7 = s7 + (1 shl 20) shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry9 = s9 + (1 shl 20) shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry11 = s11 + (1 shl 20) shr 21
        s12 += carry11
        s11 -= carry11 shl 21

        s0 += s12 * 666643
        s1 += s12 * 470296
        s2 += s12 * 654183
        s3 -= s12 * 997805
        s4 += s12 * 136657
        s5 -= s12 * 683901
        s12 = 0

        // Carry chain reduction to propagate excess bits from s0 to s5 to the most significant limbs.
        carry0 = s0 shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry1 = s1 shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry2 = s2 shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry3 = s3 shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry4 = s4 shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry5 = s5 shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry6 = s6 shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry7 = s7 shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry8 = s8 shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry9 = s9 shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry10 = s10 shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        carry11 = s11 shr 21
        s12 += carry11
        s11 -= carry11 shl 21

        // Do one last reduction as s12 might be 1.
        s0 += s12 * 666643
        s1 += s12 * 470296
        s2 += s12 * 654183
        s3 -= s12 * 997805
        s4 += s12 * 136657
        s5 -= s12 * 683901
        // s12 = 0;

        carry0 = s0 shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry1 = s1 shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry2 = s2 shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry3 = s3 shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry4 = s4 shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry5 = s5 shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry6 = s6 shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry7 = s7 shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry8 = s8 shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry9 = s9 shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry10 = s10 shr 21
        s11 += carry10
        s10 -= carry10 shl 21

        // Serialize the result into the s.
        s[0] = s0.toByte()
        s[1] = (s0 shr 8).toByte()
        s[2] = (s0 shr 16 or (s1 shl 5)).toByte()
        s[3] = (s1 shr 3).toByte()
        s[4] = (s1 shr 11).toByte()
        s[5] = (s1 shr 19 or (s2 shl 2)).toByte()
        s[6] = (s2 shr 6).toByte()
        s[7] = (s2 shr 14 or (s3 shl 7)).toByte()
        s[8] = (s3 shr 1).toByte()
        s[9] = (s3 shr 9).toByte()
        s[10] = (s3 shr 17 or (s4 shl 4)).toByte()
        s[11] = (s4 shr 4).toByte()
        s[12] = (s4 shr 12).toByte()
        s[13] = (s4 shr 20 or (s5 shl 1)).toByte()
        s[14] = (s5 shr 7).toByte()
        s[15] = (s5 shr 15 or (s6 shl 6)).toByte()
        s[16] = (s6 shr 2).toByte()
        s[17] = (s6 shr 10).toByte()
        s[18] = (s6 shr 18 or (s7 shl 3)).toByte()
        s[19] = (s7 shr 5).toByte()
        s[20] = (s7 shr 13).toByte()
        s[21] = s8.toByte()
        s[22] = (s8 shr 8).toByte()
        s[23] = (s8 shr 16 or (s9 shl 5)).toByte()
        s[24] = (s9 shr 3).toByte()
        s[25] = (s9 shr 11).toByte()
        s[26] = (s9 shr 19 or (s10 shl 2)).toByte()
        s[27] = (s10 shr 6).toByte()
        s[28] = (s10 shr 14 or (s11 shl 7)).toByte()
        s[29] = (s11 shr 1).toByte()
        s[30] = (s11 shr 9).toByte()
        s[31] = (s11 shr 17).toByte()
    }

    /**
     * Input:
     * `a[0]+256*a[1]+...+256^31*a[31] = a`
     * `b[0]+256*b[1]+...+256^31*b[31] = b`
     * `c[0]+256*c[1]+...+256^31*c[31] = c`
     *
     * Output:
     * `s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l`
     * where l = 2^252 + 27742317777372353535851937790883648493.
     */
    private fun mulAdd(
        s: ByteArray,
        a: ByteArray,
        b: ByteArray,
        c: ByteArray,
    ) {
        // This is very similar to Ed25519.reduce, the difference in here is that it computes ab+c
        // See Ed25519.reduce for related comments.
        val a0 = 2097151L and load3(a, 0)
        val a1 = 2097151L and (load4(a, 2) shr 5)
        val a2 = 2097151L and (load3(a, 5) shr 2)
        val a3 = 2097151L and (load4(a, 7) shr 7)
        val a4 = 2097151L and (load4(a, 10) shr 4)
        val a5 = 2097151L and (load3(a, 13) shr 1)
        val a6 = 2097151L and (load4(a, 15) shr 6)
        val a7 = 2097151L and (load3(a, 18) shr 3)
        val a8 = 2097151L and load3(a, 21)
        val a9 = 2097151L and (load4(a, 23) shr 5)
        val a10 = 2097151L and (load3(a, 26) shr 2)
        val a11 = load4(a, 28) shr 7
        val b0 = 2097151L and load3(b, 0)
        val b1 = 2097151L and (load4(b, 2) shr 5)
        val b2 = 2097151L and (load3(b, 5) shr 2)
        val b3 = 2097151L and (load4(b, 7) shr 7)
        val b4 = 2097151L and (load4(b, 10) shr 4)
        val b5 = 2097151L and (load3(b, 13) shr 1)
        val b6 = 2097151L and (load4(b, 15) shr 6)
        val b7 = 2097151L and (load3(b, 18) shr 3)
        val b8 = 2097151L and load3(b, 21)
        val b9 = 2097151L and (load4(b, 23) shr 5)
        val b10 = 2097151L and (load3(b, 26) shr 2)
        val b11 = load4(b, 28) shr 7
        val c0 = 2097151L and load3(c, 0)
        val c1 = 2097151L and (load4(c, 2) shr 5)
        val c2 = 2097151L and (load3(c, 5) shr 2)
        val c3 = 2097151L and (load4(c, 7) shr 7)
        val c4 = 2097151L and (load4(c, 10) shr 4)
        val c5 = 2097151L and (load3(c, 13) shr 1)
        val c6 = 2097151L and (load4(c, 15) shr 6)
        val c7 = 2097151L and (load3(c, 18) shr 3)
        val c8 = 2097151L and load3(c, 21)
        val c9 = 2097151L and (load4(c, 23) shr 5)
        val c10 = 2097151L and (load3(c, 26) shr 2)
        val c11 = load4(c, 28) shr 7

        var s0: Long = c0 + a0 * b0
        var s1: Long = c1 + a0 * b1 + a1 * b0
        var s2: Long = c2 + a0 * b2 + a1 * b1 + a2 * b0
        var s3: Long = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0
        var s4: Long = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0
        var s5: Long = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0
        var s6: Long = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0
        var s7: Long = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0
        var s8: Long = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0
        var s9: Long =
            c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0
        var s10: Long =
            c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0
        var s11: Long =
            c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0
        var s12: Long =
            a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1
        var s13: Long =
            a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2
        var s14: Long = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3
        var s15: Long = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4
        var s16: Long = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5
        var s17: Long = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6
        var s18: Long = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7
        var s19: Long = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8
        var s20: Long = a9 * b11 + a10 * b10 + a11 * b9
        var s21: Long = a10 * b11 + a11 * b10
        var s22: Long = a11 * b11
        var s23: Long = 0

        var carry0: Long = s0 + (1 shl 20) shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        var carry2: Long = s2 + (1 shl 20) shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        var carry4: Long = s4 + (1 shl 20) shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        var carry6: Long = s6 + (1 shl 20) shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        var carry8: Long = s8 + (1 shl 20) shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        var carry10: Long = s10 + (1 shl 20) shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        var carry12: Long = s12 + (1 shl 20) shr 21
        s13 += carry12
        s12 -= carry12 shl 21
        var carry14: Long = s14 + (1 shl 20) shr 21
        s15 += carry14
        s14 -= carry14 shl 21
        var carry16: Long = s16 + (1 shl 20) shr 21
        s17 += carry16
        s16 -= carry16 shl 21
        val carry18: Long = s18 + (1 shl 20) shr 21
        s19 += carry18
        s18 -= carry18 shl 21
        val carry20: Long = s20 + (1 shl 20) shr 21
        s21 += carry20
        s20 -= carry20 shl 21
        val carry22: Long = s22 + (1 shl 20) shr 21
        s23 += carry22
        s22 -= carry22 shl 21

        var carry1: Long = s1 + (1 shl 20) shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        var carry3: Long = s3 + (1 shl 20) shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        var carry5: Long = s5 + (1 shl 20) shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        var carry7: Long = s7 + (1 shl 20) shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        var carry9: Long = s9 + (1 shl 20) shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        var carry11: Long = s11 + (1 shl 20) shr 21
        s12 += carry11
        s11 -= carry11 shl 21
        var carry13: Long = s13 + (1 shl 20) shr 21
        s14 += carry13
        s13 -= carry13 shl 21
        var carry15: Long = s15 + (1 shl 20) shr 21
        s16 += carry15
        s15 -= carry15 shl 21
        val carry17: Long = s17 + (1 shl 20) shr 21
        s18 += carry17
        s17 -= carry17 shl 21
        val carry19: Long = s19 + (1 shl 20) shr 21
        s20 += carry19
        s19 -= carry19 shl 21
        val carry21: Long = s21 + (1 shl 20) shr 21
        s22 += carry21
        s21 -= carry21 shl 21

        s11 += s23 * 666643
        s12 += s23 * 470296
        s13 += s23 * 654183
        s14 -= s23 * 997805
        s15 += s23 * 136657
        s16 -= s23 * 683901
        // s23 = 0;

        s10 += s22 * 666643
        s11 += s22 * 470296
        s12 += s22 * 654183
        s13 -= s22 * 997805
        s14 += s22 * 136657
        s15 -= s22 * 683901
        // s22 = 0;

        s9 += s21 * 666643
        s10 += s21 * 470296
        s11 += s21 * 654183
        s12 -= s21 * 997805
        s13 += s21 * 136657
        s14 -= s21 * 683901
        // s21 = 0;

        s8 += s20 * 666643
        s9 += s20 * 470296
        s10 += s20 * 654183
        s11 -= s20 * 997805
        s12 += s20 * 136657
        s13 -= s20 * 683901
        // s20 = 0;

        s7 += s19 * 666643
        s8 += s19 * 470296
        s9 += s19 * 654183
        s10 -= s19 * 997805
        s11 += s19 * 136657
        s12 -= s19 * 683901
        // s19 = 0;

        s6 += s18 * 666643
        s7 += s18 * 470296
        s8 += s18 * 654183
        s9 -= s18 * 997805
        s10 += s18 * 136657
        s11 -= s18 * 683901
        // s18 = 0;

        carry6 = s6 + (1 shl 20) shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry8 = s8 + (1 shl 20) shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry10 = s10 + (1 shl 20) shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        carry12 = s12 + (1 shl 20) shr 21
        s13 += carry12
        s12 -= carry12 shl 21
        carry14 = s14 + (1 shl 20) shr 21
        s15 += carry14
        s14 -= carry14 shl 21
        carry16 = s16 + (1 shl 20) shr 21
        s17 += carry16
        s16 -= carry16 shl 21

        carry7 = s7 + (1 shl 20) shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry9 = s9 + (1 shl 20) shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry11 = s11 + (1 shl 20) shr 21
        s12 += carry11
        s11 -= carry11 shl 21
        carry13 = s13 + (1 shl 20) shr 21
        s14 += carry13
        s13 -= carry13 shl 21
        carry15 = s15 + (1 shl 20) shr 21
        s16 += carry15
        s15 -= carry15 shl 21

        s5 += s17 * 666643
        s6 += s17 * 470296
        s7 += s17 * 654183
        s8 -= s17 * 997805
        s9 += s17 * 136657
        s10 -= s17 * 683901
        // s17 = 0;

        s4 += s16 * 666643
        s5 += s16 * 470296
        s6 += s16 * 654183
        s7 -= s16 * 997805
        s8 += s16 * 136657
        s9 -= s16 * 683901
        // s16 = 0;

        s3 += s15 * 666643
        s4 += s15 * 470296
        s5 += s15 * 654183
        s6 -= s15 * 997805
        s7 += s15 * 136657
        s8 -= s15 * 683901
        // s15 = 0;

        s2 += s14 * 666643
        s3 += s14 * 470296
        s4 += s14 * 654183
        s5 -= s14 * 997805
        s6 += s14 * 136657
        s7 -= s14 * 683901
        // s14 = 0;

        s1 += s13 * 666643
        s2 += s13 * 470296
        s3 += s13 * 654183
        s4 -= s13 * 997805
        s5 += s13 * 136657
        s6 -= s13 * 683901
        // s13 = 0;

        s0 += s12 * 666643
        s1 += s12 * 470296
        s2 += s12 * 654183
        s3 -= s12 * 997805
        s4 += s12 * 136657
        s5 -= s12 * 683901
        s12 = 0

        carry0 = s0 + (1 shl 20) shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry2 = s2 + (1 shl 20) shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry4 = s4 + (1 shl 20) shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry6 = s6 + (1 shl 20) shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry8 = s8 + (1 shl 20) shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry10 = s10 + (1 shl 20) shr 21
        s11 += carry10
        s10 -= carry10 shl 21

        carry1 = s1 + (1 shl 20) shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry3 = s3 + (1 shl 20) shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry5 = s5 + (1 shl 20) shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry7 = s7 + (1 shl 20) shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry9 = s9 + (1 shl 20) shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry11 = s11 + (1 shl 20) shr 21
        s12 += carry11
        s11 -= carry11 shl 21

        s0 += s12 * 666643
        s1 += s12 * 470296
        s2 += s12 * 654183
        s3 -= s12 * 997805
        s4 += s12 * 136657
        s5 -= s12 * 683901
        s12 = 0

        carry0 = s0 shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry1 = s1 shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry2 = s2 shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry3 = s3 shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry4 = s4 shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry5 = s5 shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry6 = s6 shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry7 = s7 shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry8 = s8 shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry9 = s9 shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry10 = s10 shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        carry11 = s11 shr 21
        s12 += carry11
        s11 -= carry11 shl 21

        s0 += s12 * 666643
        s1 += s12 * 470296
        s2 += s12 * 654183
        s3 -= s12 * 997805
        s4 += s12 * 136657
        s5 -= s12 * 683901
        // s12 = 0;

        carry0 = s0 shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry1 = s1 shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry2 = s2 shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry3 = s3 shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry4 = s4 shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry5 = s5 shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry6 = s6 shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry7 = s7 shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry8 = s8 shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry9 = s9 shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry10 = s10 shr 21
        s11 += carry10
        s10 -= carry10 shl 21

        s[0] = s0.toByte()
        s[1] = (s0 shr 8).toByte()
        s[2] = (s0 shr 16 or (s1 shl 5)).toByte()
        s[3] = (s1 shr 3).toByte()
        s[4] = (s1 shr 11).toByte()
        s[5] = (s1 shr 19 or (s2 shl 2)).toByte()
        s[6] = (s2 shr 6).toByte()
        s[7] = (s2 shr 14 or (s3 shl 7)).toByte()
        s[8] = (s3 shr 1).toByte()
        s[9] = (s3 shr 9).toByte()
        s[10] = (s3 shr 17 or (s4 shl 4)).toByte()
        s[11] = (s4 shr 4).toByte()
        s[12] = (s4 shr 12).toByte()
        s[13] = (s4 shr 20 or (s5 shl 1)).toByte()
        s[14] = (s5 shr 7).toByte()
        s[15] = (s5 shr 15 or (s6 shl 6)).toByte()
        s[16] = (s6 shr 2).toByte()
        s[17] = (s6 shr 10).toByte()
        s[18] = (s6 shr 18 or (s7 shl 3)).toByte()
        s[19] = (s7 shr 5).toByte()
        s[20] = (s7 shr 13).toByte()
        s[21] = s8.toByte()
        s[22] = (s8 shr 8).toByte()
        s[23] = (s8 shr 16 or (s9 shl 5)).toByte()
        s[24] = (s9 shr 3).toByte()
        s[25] = (s9 shr 11).toByte()
        s[26] = (s9 shr 19 or (s10 shl 2)).toByte()
        s[27] = (s10 shr 6).toByte()
        s[28] = (s10 shr 14 or (s11 shl 7)).toByte()
        s[29] = (s11 shr 1).toByte()
        s[30] = (s11 shr 9).toByte()
        s[31] = (s11 shr 17).toByte()
    }

    fun getHashedScalar(privateKey: ByteArray): ByteArray {
        val h = SHA512().digest(privateKey)
        // https://tools.ietf.org/html/rfc8032#section-5.1.2.
        // Clear the lowest three bits of the first octet.
        h[0] = (h[0].toInt() and 248).toByte()
        // Clear the highest bit of the last octet.
        h[31] = (h[31].toInt() and 127).toByte()
        // Set the second highest bit if the last octet.
        h[31] = (h[31].toInt() or 64).toByte()
        return h
    }

    /**
     * Returns the EdDSA signature for the [message] based on the [hashedPrivateKey].
     *
     * @param message to sign
     * @param publicKey [Ed25519.scalarMultToBytes] of [hashedPrivateKey]
     * @param hashedPrivateKey [Ed25519.getHashedScalar] of the private key
     * @return signature for the [message].
     */
    fun sign(message: ByteArray, publicKey: ByteArray, hashedPrivateKey: ByteArray): ByteArray {
        val digest = Buffer().apply {
            write(hashedPrivateKey, Field25519.FIELD_LEN, Field25519.FIELD_LEN + Field25519.FIELD_LEN)
            write(message)
        }
        val r = SHA512().digest(digest.readByteArray())
        reduce(r)

        val rB = scalarMultWithBase(r).toBytes().copyOfRange(0, Field25519.FIELD_LEN)
        digest.apply {
            clear()
            write(rB)
            write(publicKey)
            write(message)
        }
        val hram = SHA512().digest(digest.readByteArray())
        reduce(hram)
        val s = ByteArray(Field25519.FIELD_LEN)
        mulAdd(s, hram, hashedPrivateKey, r)

        return Buffer().apply {
            write(rB)
            write(s)
        }.readByteArray()
    }

    /**
     * Checks whether s represents an integer smaller than the order of the group.
     * This is needed to ensure that EdDSA signatures are non-malleable, as failing to check
     * the range of S allows to modify signatures (cf. RFC 8032, Section 5.2.7 and Section 8.4.)
     * @param s an integer in little-endian order.
     */
    private fun isSmallerThanGroupOrder(s: ByteArray): Boolean {
        for (j in Field25519.FIELD_LEN - 1 downTo 0) {
            // compare unsigned bytes
            val a = s[j].toInt() and 0xff
            val b = GROUP_ORDER[j].toInt() and 0xff
            if (a != b) {
                return a < b
            }
        }
        return false
    }

    fun sign(message: ByteArray, privateKey: ByteArray): ByteArray {
        val hashedPrivateKey = getHashedScalar(privateKey)
        val publicKey = scalarMultWithBaseToBytes(hashedPrivateKey)
        return sign(message, publicKey, hashedPrivateKey)
    }

    fun verify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        if (signature.size != SIGNATURE_LEN) {
            return false
        }
        val s = signature.copyOfRange(Field25519.FIELD_LEN, SIGNATURE_LEN)
        if (!isSmallerThanGroupOrder(s)) {
            return false
        }
        val digest = Buffer().apply {
            write(signature, 0, Field25519.FIELD_LEN)
            write(publicKey)
            write(message)
        }
        val h = SHA512().digest(digest.readByteArray())
        reduce(h)

        val negPublicKey = XYZT.fromBytesNegateVarTime(publicKey)
        val xyz = doubleScalarMultVarTime(h, negPublicKey, s)
        val expectedR = xyz.toBytes()
        for (i in 0 until Field25519.FIELD_LEN) {
            if (expectedR[i] != signature[i]) {
                return false
            }
        }
        return true
    }
}
