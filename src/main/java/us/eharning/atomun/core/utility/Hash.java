/*
 * Copyright 2015, 2016 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.core.utility;

import com.google.common.annotations.Beta;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class to perform specific necessary hash functions.
 */
@Beta
public final class Hash {
    /**
     * Prevent construction as this is a static utility class.
     */
    private Hash() {
    }

    /**
     * Perform the double-hash of the encoded public key per Bitcoin rules.
     *
     * @param key
     *         ASN.1 encoded public key bytes.
     *
     * @return byte array representing the double-hashed value.
     */
    public static byte[] keyHash(byte[] key) {
        byte[] ph = new byte[20];
        byte[] sha256 = Hashing.sha256().hashBytes(key).asBytes();
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(sha256, 0, sha256.length);
        digest.doFinal(ph, 0);
        return ph;
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
    public static byte[] doubleHash(byte[] data, int offset, int len) {
        HashCode code = Hashing.sha256().hashBytes(data, offset, len);
        return Hashing.sha256().hashBytes(code.asBytes()).asBytes();
    }

    /**
     * Perform a double SHA-256 hash of the given input data.
     *
     * @param data
     *         byte array to process as input.
     *
     * @return SHA-256 digest of the data used.
     */
    public static byte[] doubleHash(byte[] data) {
        return doubleHash(data, 0, data.length);
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
    public static byte[] hash(byte[] data, int offset, int len) {
        return Hashing.sha256().hashBytes(data, offset, len).asBytes();
    }

    /**
     * Perform a double SHA-256 hash of the given input data.
     *
     * @param data
     *         byte array to process as input.
     *
     * @return SHA-256 digest of the data used.
     */
    public static byte[] hash(byte[] data) {
        return hash(data, 0, data.length);
    }
}
