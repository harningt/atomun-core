/*
 * Copyright 2014, 2015, 2016, 2017 Thomas Harning Jr. <harningt@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package us.eharning.atomun.core.crypto

import us.eharning.atomun.core.annotations.Beta
import java.lang.System.arraycopy
import java.security.GeneralSecurityException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

/**
 * Internal implementation of PBKDF2 layered atop standard primitives for more flexibility.
 */
@Beta
object PBKDF2 {

    /**
     * Implementation of PBKDF2 (RFC2898).
     * @param alg
     *         HMAC algorithm to use.
     * @param P
     *         Password.
     * @param S
     *         Salt.
     * @param c
     *         Iteration count.
     * @param dkLen
     *         Intended length, in octets, of the derived key.
     *
     * @return The derived key.
     *
     * @throws GeneralSecurityException
     *         If algorithm retrieval fails or key parameters are invalid.
     */
    @JvmStatic
    @SuppressWarnings("checkstyle:parametername", "checkstyle:localvariablename")
    @Throws(GeneralSecurityException::class)
    fun pbkdf2(alg: String, P: ByteArray, S: ByteArray, c: Int, dkLen: Int): ByteArray {
        val mac = Mac.getInstance(alg)
        mac.init(SecretKeySpec(P, alg))
        val DK = ByteArray(dkLen)
        pbkdf2(mac, S, c, DK, dkLen)
        return DK
    }

    /**
     * Implementation of PBKDF2 (RFC2898).
     *
     * @param mac
     *         Pre-initialized [Mac] instance to use.
     * @param S
     *         Salt.
     * @param c
     *         Iteration count.
     * @param DK
     *         Byte array that derived key will be placed in.
     * @param dkLen
     *         Intended length, in octets, of the derived key.
     *
     * @throws GeneralSecurityException
     *         If key parameters are invalid.
     */
    @JvmStatic
    @SuppressWarnings("checkstyle:parametername", "checkstyle:localvariablename")
    @Throws(GeneralSecurityException::class)
    fun pbkdf2(mac: Mac, S: ByteArray, c: Int, DK: ByteArray, dkLen: Int) {
        val hLen = mac.macLength

        /* Key length cannot possibly be larger than PBKDF2 limit since length type is signed int */
        assert(dkLen <= (Math.pow(2.0, 32.0) - 1) * hLen)
        /* Cannot store more than dkLen in smaller array */

        require(dkLen <= DK.size, { "($dkLen) must not be greater than size of the output array (${DK.size})" })

        val U = ByteArray(hLen)
        val T = ByteArray(hLen)
        val block1 = ByteArray(S.size + 4)

        val l = Math.ceil(dkLen.toDouble() / hLen).toInt()
        val r = dkLen - (l - 1) * hLen

        arraycopy(S, 0, block1, 0, S.size)

        for (i in 1..l) {
            block1[S.size + 0] = (i shr 24 and 0xff).toByte()
            block1[S.size + 1] = (i shr 16 and 0xff).toByte()
            block1[S.size + 2] = (i shr 8 and 0xff).toByte()
            block1[S.size + 3] = (i shr 0 and 0xff).toByte()

            mac.update(block1)
            mac.doFinal(U, 0)
            arraycopy(U, 0, T, 0, hLen)

            for (j in 1..c - 1) {
                mac.update(U)
                mac.doFinal(U, 0)

                for (k in 0..hLen - 1) {
                    T[k] = T[k] xor U[k]
                }
            }

            arraycopy(T, 0, DK, (i - 1) * hLen, if (i == l) r else hLen)
        }
    }
}