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

package us.eharning.atomun.core.ec.internal

import com.google.common.base.Objects
import com.google.common.base.Preconditions
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import us.eharning.atomun.core.ValidationException
import us.eharning.atomun.core.ec.ECDSA
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.ec.internal.BouncyCastleECKeyConstants.CURVE
import us.eharning.atomun.core.encoding.Base58

import java.math.BigInteger
import java.security.SecureRandom
import java.util.Arrays
import javax.annotation.concurrent.Immutable

/**
 * ECKey implementation wrapping a full keypair using BouncyCastle.
 */
@Immutable
open class BouncyCastleECKeyPair
/**
 * Construct a new EC keypair given the private exponent, its public point, and whether or not to use compressed point form.
 *
 * @param privateExponent
 *         value defining the private key.
 * @param encodedPublicKey
 *         DER-encoded public point associated with the given private key.
 *         If not set - it is calculated from the private exponent.
 * @param compressed
 *         whether or not to use compressed point form.
 */
constructor (
        internal val privateExponent: BigInteger,
        encodedPublicKey: ByteArray? = null,
        compressed: Boolean
) : BouncyCastleECPublicKey(encodedPublicKey ?: CURVE.g.multiply(privateExponent).getEncoded(compressed), compressed) {

    /**
     * Export the private key in bitcoin 'standard' form - exactly 32-bytes.
     *
     * @return exported 32-byte private key.
     */
    override fun exportPrivate(): ByteArray? {
        var privateBytes = privateExponent.toByteArray()
        if (privateBytes.size != 32) {
            val tmp = ByteArray(32)
            System.arraycopy(privateBytes, Math.max(0, privateBytes.size - 32), tmp, Math.max(0, 32 - privateBytes.size), Math.min(32, privateBytes.size))
            privateBytes = tmp
        }
        return privateBytes
    }

    /**
     * Returns whether or not this keypair is populated with the private key.
     *
     * @return true - the private key is present.
     */
    override fun hasPrivate(): Boolean {
        return true
    }

    /**
     * Obtain a reference to this key, just including public pieces.
     *
     * @return instance with just public data present.
     */
    override val public: ECKey
        get() = BouncyCastleECPublicKey(encodedPublicKey, compressed)

    /**
     * Obtain a reference to the ECDSA operator for this key.
     *
     * @return instance with appropriate ECDSA capabilities.
     */
    override val ECDSA: ECDSA
        get() = BouncyCastleECSigner.fromPrivateKey(this)

    /**
     * Convert this instance to a string form - which happens to be the serialized WIF form.
     *
     * @return display string.
     */
    override fun toString(): String {
        return serializeWIF(this)
    }

    /**
     * Return true if this is equivalent to the passed in object (same type and same properties)
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
        other as BouncyCastleECKeyPair
        return Objects.equal(compressed, other.compressed)
                && Arrays.equals(encodedPublicKey, other.encodedPublicKey)
                && Objects.equal(privateExponent, other.privateExponent)
    }

    /**
     * Returns a hash code value for the object.
     *
     * @return a hash code value for this object.
     */
    override fun hashCode(): Int {
        return Objects.hashCode(compressed, Arrays.hashCode(encodedPublicKey), privateExponent)
    }

    companion object {
        private val secureRandom = SecureRandom()

        /**
         * Utility method to create a new random EC keypair.
         *
         * @param compressed
         *         whether or not to use compressed point form.
         *
         * @return random EC keypair.
         */
        @JvmStatic
        fun createNew(compressed: Boolean): BouncyCastleECKeyPair {
            val generator = ECKeyPairGenerator()
            val keygenParams = ECKeyGenerationParameters(BouncyCastleECKeyConstants.DOMAIN, secureRandom)
            generator.init(keygenParams)
            val keypair = generator.generateKeyPair()
            val privParams = keypair.private as ECPrivateKeyParameters
            val pubParams = keypair.public as ECPublicKeyParameters

            return BouncyCastleECKeyPair(privParams.d, pubParams.q.getEncoded(compressed), compressed)
        }

        /**
         * Import the serialized EC private key given its private exponent as a byte array.
         *
         * @param serializedPrivateExponent
         *         byte array containing value defining the private key.
         * @param compressed
         *         whether or not to use compressed point form.
         *
         * @return the decoded EC private key.
         *
         * @throws ValidationException
         *         if the key is invalid.
         */
        @JvmStatic
        @Throws(ValidationException::class)
        fun importSerialized(serializedPrivateExponent: ByteArray, compressed: Boolean): BouncyCastleECKeyPair {
            Preconditions.checkNotNull(serializedPrivateExponent)
            if (serializedPrivateExponent.size != 32) {
                throw ValidationException("Invalid private key")
            }
            return BouncyCastleECKeyPair(BigInteger(1, serializedPrivateExponent).mod(CURVE.n), null, compressed)
        }

        /**
         * Serialize the EC keypair in WIF Base58-encoded form.
         *
         * @param key
         *         instance to serialize.
         *
         * @return serialized EC keypair.
         */
        @JvmStatic
        fun serializeWIF(key: BouncyCastleECKeyPair): String {
            return Base58.encodeWithChecksum(bytesWIF(key))
        }

        /**
         * Serialize the EC keypair as a WIF byte array.
         *
         * @param key
         *         instance to serialize.
         *
         * @return serialized EC keypair.
         */
        @SuppressWarnings("checkstyle:localvariablename")
        private fun bytesWIF(key: BouncyCastleECKeyPair): ByteArray {
            val k = key.exportPrivate()!!
            if (key.compressed) {
                val ek = ByteArray(k.size + 2)
                ek[0] = 0x80.toByte()
                System.arraycopy(k, 0, ek, 1, k.size)
                ek[k.size + 1] = 0x01
                return ek
            } else {
                val ek = ByteArray(k.size + 1)
                ek[0] = 0x80.toByte()
                System.arraycopy(k, 0, ek, 1, k.size)
                return ek
            }
        }

        /**
         * Parse a key in WIF base64-encoded form.
         *
         * @param serialized
         *         base64-encoded WIF-encoded EC key
         *
         * @return decoded key
         *
         * @throws ValidationException
         *         if the key is invalid.
         */
        @JvmStatic
        @Throws(ValidationException::class)
        fun parseWIF(serialized: String): BouncyCastleECKeyPair {
            val store = Base58.decodeWithChecksum(serialized)
            return parseBytesWIF(store)
        }

        /**
         * Parse a key in WIF byte-data form.
         *
         * @param store
         *         WIF-encoded EC key
         *
         * @return decoded key
         *
         * @throws ValidationException
         *         if the key is invalid.
         */
        @JvmStatic
        @Throws(ValidationException::class)
        fun parseBytesWIF(store: ByteArray): BouncyCastleECKeyPair {
            if (store.size == 33) {
                val key = ByteArray(store.size - 1)
                System.arraycopy(store, 1, key, 0, store.size - 1)
                return importSerialized(key, false)
            } else if (store.size == 34) {
                val key = ByteArray(store.size - 2)
                System.arraycopy(store, 1, key, 0, store.size - 2)
                return importSerialized(key, true)
            }
            throw ValidationException("Invalid key length")
        }
    }
}
