/*
 * Copyright 2015, 2017 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.core.utility

import org.bouncycastle.crypto.digests.RIPEMD160Digest
import us.eharning.atomun.core.annotations.Beta
import java.security.DigestException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * Utility class to perform specific necessary hash functions.
 */
@Beta
object Hash {
    private const val SHA256_DIGEST_LEN = 32

    /**
     * Perform the double-hash of the encoded public key per Bitcoin rules.
     *
     * @param key
     *         ASN.1 encoded public key bytes.
     *
     * @return byte array representing the double-hashed value.
     */
    @JvmStatic
    fun keyHash(key: ByteArray): ByteArray {
        val ph = ByteArray(20)
        keyHash(key, 0, key.size, ph, 0)
        return ph
    }

    /**
     * Perform the double-hash of the encoded public key per Bitcoin rules.
     *
     * @param key       byte array to process as input.
     * @param offset    offset into the byte array.
     * @param len       number of bytes to process from the byte array.
     * @param result    byte array to write results to.
     * @param resultOffset  offset into the result byte array.
     *
     * @return length of digest added to buffer.
     */
    @JvmStatic
    fun keyHash(key: ByteArray, offset: Int, len: Int, result: ByteArray, resultOffset: Int): Int {
        try {
            val sha256digest = MessageDigest.getInstance("SHA-256")
            sha256digest.update(key, offset, len)
            val sha256 = sha256digest.digest()
            val digest = RIPEMD160Digest()
            digest.update(sha256, 0, sha256.size)
            return digest.doFinal(result, resultOffset)
        } catch (e: NoSuchAlgorithmException) {
            throw Error("Missing SHA-256 / failed setup", e)
        }
    }

    /**
     * Perform a double SHA-256 hash of the given input data.
     *
     * @param data
     *         byte array to process as input.
     * @param offset
     *         offset into the byte array.
     * @param len
     *         number of bytes to process from the byte array.
     * @param result
     *         byte array to write results to.
     * @param resultOffset
     *         offset into the result byte array.
     * @param resultLen
     *         number of bytes set aside for the result byte array.
     *
     * @return length of digest added to buffer.
     */
    @JvmStatic
    fun doubleHash(data: ByteArray, offset: Int, len: Int, result: ByteArray, resultOffset: Int, resultLen: Int): Int {
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(data, offset, len)
            /* Perform first digest pass - which resets state */
            digest.digest(result, resultOffset, resultLen)
            /* Feed in digest data */
            digest.update(result, resultOffset, resultLen)
            /* Perform second digest pass */
            return digest.digest(result, resultOffset, resultLen)
        } catch (e: DigestException) {
            throw Error("Missing SHA-256 / failed setup", e)
        } catch (e: NoSuchAlgorithmException) {
            throw Error("Missing SHA-256 / failed setup", e)
        }
    }

    /**
     * Perform a double SHA-256 hash of the given input data.
     *
     * @param data
     *         byte array to process as input.
     * @param offset
     *         offset into the byte array.
     * @param len
     *         number of bytes to process from the byte array.
     *
     * @return SHA-256 digest of the data used.
     */
    @JvmStatic
    @JvmOverloads
    fun doubleHash(data: ByteArray, offset: Int = 0, len: Int = data.size): ByteArray {
        val result = ByteArray(SHA256_DIGEST_LEN)
        doubleHash(data, offset, len, result, 0, result.size)
        return result
    }

    /**
     * Perform a SHA-256 hash of the given input data.
     *
     * @param data
     *         byte array to process as input.
     * @param offset
     *         offset into the byte array.
     * @param len
     *         number of bytes to process from the byte array.
     *
     * @return SHA-256 digest of the data used.
     */
    @JvmStatic
    @JvmOverloads
    fun hash(data: ByteArray, offset: Int = 0, len: Int = data.size): ByteArray {
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(data, offset, len)
            return digest.digest()
        } catch (e: NoSuchAlgorithmException) {
            throw Error("Missing SHA-256", e)
        }
    }
}
