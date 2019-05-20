/*
 * Copyright 2015, 2016, 2017 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.core.ec.internal

import us.eharning.atomun.core.ec.ECDSA
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.utility.Hash
import java.util.*
import javax.annotation.concurrent.Immutable

/**
 * ECKey implementation wrapping a public key using BouncyCastle.
 */
@Immutable
open class BouncyCastleECPublicKey
/**
 * Construct a public key from the given encoded public key and whether or not to treat is as compressed.
 *
 * @param encodedPublicKey
 *         DER-encoded EC public key.
 * @param compressed
 *         whether or not the EC public key is in compressed point form.
 */
constructor (
        encodedPublicKey: ByteArray,
        protected val compressed: Boolean
) : ECKey {

    protected val encodedPublicKey: ByteArray = encodedPublicKey.copyOf()

    /**
     * Obtain the 'address hash' per Bitcoin rules.
     *
     * @return 20-byte address hash byte array
     */
    override val addressHash: ByteArray
        get() = Hash.keyHash(encodedPublicKey)

    /**
     * Export the private key in bitcoin 'standard' form - exactly 32-bytes.
     *
     * @return exported 32-byte private key or null if not present.
     */
    override fun exportPrivate(): ByteArray? {
        return null
    }

    /**
     * Returns whether or not this keypair is populated with the private key.
     *
     * @return false - the private key is not present.
     */
    override fun hasPrivate(): Boolean {
        return false
    }

    /**
     * Export the public key in ASN.1-encoded form.
     *
     * @return ASN.1 encoded public key bytes.
     */
    override fun exportPublic(): ByteArray {
        return encodedPublicKey.copyOf()
    }

    /**
     * Obtain a reference to this key, just including public pieces.
     *
     * @return instance with just public data present.
     */
    override val public: ECKey
        get() = this

    /**
     * Obtain a reference to the ECDSA operator for this key.
     *
     * @return instance with appropriate ECDSA capabilities.
     */
    override val ECDSA: ECDSA
        get() = BouncyCastleECSigner.fromPublicKey(this)

    /**
     * Return true if this is equivalent to the passed in object (same type and same properties).
     *
     * @param other
     *         instance to compare against.
     *
     * @return true if the values are equivalent, else false.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other?.javaClass != javaClass) {
            return false
        }
        other as BouncyCastleECPublicKey
        return compressed == other.compressed
                && Arrays.equals(encodedPublicKey, other.encodedPublicKey)
    }

    override fun hashCode(): Int {
        var result = compressed.hashCode()
        result = 31 * result + Arrays.hashCode(encodedPublicKey)
        return result
    }
}
