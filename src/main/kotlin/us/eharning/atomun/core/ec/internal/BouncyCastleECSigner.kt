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

package us.eharning.atomun.core.ec.internal

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequenceGenerator
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.math.ec.ECPoint
import us.eharning.atomun.core.ec.ECDSA
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.ec.internal.BouncyCastleECKeyConstants.CURVE
import us.eharning.atomun.core.ec.internal.BouncyCastleECKeyConstants.DOMAIN
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import javax.annotation.concurrent.Immutable

/**
 * Signature implementation using exposed secret exponent / public ECPoint.
 */
@Immutable
internal class BouncyCastleECSigner
/**
 * Construct a signature operation with the given key material.
 *
 * @param privateExponent
 *         Private exponent from EC key - if present, signatures are allowed.
 * @param publicPoint
 *         Public point on the Elliptical Curve, verification is dependent on this.
 * @param canonicalize
 *         If true, then the signature point is canonicalized.
 */
@JvmOverloads constructor(
        private val privateExponent: BigInteger?,
        private val publicPoint: ECPoint,
        private val canonicalize: Boolean = true
) : ECDSA {

    /**
     * Obtain an ECDSA instance with the given canonicalization bit set.
     *
     * @param canonicalize
     *         If true, then the signature point is canonicalized.
     *
     * @return
     *         ECDSA instance with canonicalization set to the given value.
     */
    fun withCanonicalize(canonicalize: Boolean): BouncyCastleECSigner {
        if (this.canonicalize == canonicalize) {
            return this
        }
        return BouncyCastleECSigner(privateExponent, publicPoint, canonicalize)
    }

    /**
     * Perform an ECDSA signature using the private key.
     *
     * @param hash
     *         byte array to sign.
     *
     * @return ASN.1 representation of the signature.
     */
    override fun sign(hash: ByteArray): ByteArray {
        if (null == privateExponent) {
            throw UnsupportedOperationException("Cannot sign with public key")
        }
        /* The HMacDSAKCalculator is what makes this signer RFC 6979 compliant. */
        val signer = ECDSASigner(RFC6979KCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(privateExponent, DOMAIN))
        val signature = signer.generateSignature(hash)
        /* Need to canonicalize signature up front ... */
        if (canonicalize && signature[1].compareTo(HALF_CURVE_ORDER) > 0) {
            /* BOP does not do this */
            signature[1] = CURVE.n.subtract(signature[1])
        }
        return calculateSignature(signature)
    }

    /**
     * Convert the DSA signature-parts into a byte array.
     *
     * @param signature
     *          ECDSA signature to convert.
     *
     * @return
     *          byte[] for of signature.
     */
    @Throws(IOException::class)
    fun calculateSignature(signature: Array<BigInteger>): ByteArray {
        val stream = ByteArrayOutputStream()
        val seq = DERSequenceGenerator(stream)
        seq.addObject(ASN1Integer(signature[0]))
        seq.addObject(ASN1Integer(signature[1]))
        seq.close()
        return stream.toByteArray()
    }

    /**
     * Verify an ECDSA signature using the public key.
     *
     * @param hash
     *         byte array of the hash to verify.
     * @param signature
     *         ASN.1 representation of the signature to verify hash with.
     *
     * @return true if the signature matches, else false.
     */
    @SuppressWarnings("checkstyle:localvariablename")
    override fun verify(hash: ByteArray, signature: ByteArray): Boolean {
        try {
            val signer = ECDSASigner()
            signer.init(false, ECPublicKeyParameters(publicPoint, DOMAIN))
            val seq = ASN1Sequence.getInstance(signature)
            val r = seq.getObjectAt(0)
            val s = seq.getObjectAt(1)
            if (r !is ASN1Integer || s !is ASN1Integer) {
                return false
            }
            return signer.verifySignature(hash, r.positiveValue, s.positiveValue)
        } catch (e: Throwable) {
            // treat format errors as invalid signatures
            return false
        }
    }

    companion object {
        private val HALF_CURVE_ORDER = CURVE.n.shiftRight(1)

        /**
         * Obtain a signer given a private key - specifically a BouncyCastleECKeyPair.
         *
         * @param privateKey
         *         Key instance to collect data for signing from.
         *
         * @return
         *         ECDSA instance capable of signature and verification.
         */
        @JvmStatic
        fun fromPrivateKey(privateKey: ECKey): BouncyCastleECSigner {
            assert(privateKey is BouncyCastleECKeyPair)
            val publicPoint = CURVE.curve.decodePoint(privateKey.exportPublic())
            val privateExponent = (privateKey as BouncyCastleECKeyPair).privateExponent
            return BouncyCastleECSigner(privateExponent, publicPoint)
        }

        /**
         * Obtain a signer given any public key.
         *
         * @param publicKey
         *         Key instance to collect data for verification from.
         *
         * @return
         *         ECDSA instance capable of verification.
         */
        @JvmStatic
        fun fromPublicKey(publicKey: ECKey): BouncyCastleECSigner {
            val publicPoint = CURVE.curve.decodePoint(publicKey.exportPublic())
            return BouncyCastleECSigner(null, publicPoint)
        }
    }
}