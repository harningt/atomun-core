/*
 * Copyright 2016, 2017 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.core.ec

/**
 * Utility interface wrapping ECDSA operations.
 */
interface ECDSA {
    /**
     * Perform an ECDSA signature using the private key.

     * @param hash
     * *         byte array to sign.
     * *
     * *
     * @return ASN.1 representation of the signature.
     * *
     * @throws UnsupportedOperationException if only the public key is available
     */
    fun sign(hash: ByteArray): ByteArray

    /**
     * Verify an ECDSA signature using the public key.

     * @param hash
     * *         byte array of the hash to verify.
     * *
     * @param signature
     * *         ASN.1 representation of the signature to verify hash with.
     * *
     * *
     * @return true if the signature matches, else false.
     */
    fun verify(hash: ByteArray, signature: ByteArray): Boolean
}
