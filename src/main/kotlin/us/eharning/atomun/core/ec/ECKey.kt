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

package us.eharning.atomun.core.ec

import javax.annotation.concurrent.Immutable

/**
 * Base Elliptical Cryptography keypair interface.
 *
 *
 * Likely to change in the future and be pushed to a common library.
 *
 */
@Immutable
interface ECKey {
    /**
     * Export the private key in bitcoin 'standard' form - exactly 32-bytes.

     * @return exported 32-byte private key or null if not present.
     */
    fun exportPrivate(): ByteArray?

    /**
     * Returns whether or not this keypair is populated with the private key.

     * @return true if the private key is present.
     */
    fun hasPrivate(): Boolean

    /**
     * Export the public key in ASN.1-encoded form.

     * @return ASN.1 encoded public key bytes.
     */
    fun exportPublic(): ByteArray

    /**
     * Obtain the 'address hash' per Bitcoin rules.

     * @return 20-byte address hash byte array
     */
    val addressHash: ByteArray

    /**
     * Obtain a reference to this key, just including public pieces.

     * @return instance with just public data present.
     */
    val public: ECKey

    /**
     * Obtain a reference to the ECDSA operator for this key.

     * @return instance with appropriate ECDSA capabilities.
     */
    val ECDSA: ECDSA
}
