/*
 * Copyright 2016 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.core.ec.internal;

import static us.eharning.atomun.core.ec.internal.BouncyCastleECKeyConstants.CURVE;
import static us.eharning.atomun.core.ec.internal.BouncyCastleECKeyConstants.DOMAIN;

import com.google.common.base.Verify;
import com.google.common.io.Closeables;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import us.eharning.atomun.core.ec.ECDSA;
import us.eharning.atomun.core.ec.ECKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * Signature implementation using exposed secret exponent / public ECPoint.
 */
@Immutable
class BouncyCastleECSigner implements ECDSA {
    private static final BigInteger HALF_CURVE_ORDER = CURVE.getN().shiftRight(1);

    /**
     * Canonicalization flag - default true, but can be disabled in unit tests.
     */
    private final boolean canonicalize;

    /**
     * Private exponent from EC key - if present, signatures are allowed.
     */
    @Nullable
    private final BigInteger privateExponent;

    /**
     * Public point on the Elliptical Curve, verification is dependent on this.
     */
    @Nonnull
    private final ECPoint publicPoint;

    /**
     * Construct a signature operation with the given key material.
     *
     * @param privateExponent
     *         Private exponent from EC key - if present, signatures are allowed.
     * @param publicPoint
     *         Public point on the Elliptical Curve, verification is dependent on this.
     */
    BouncyCastleECSigner(@Nullable BigInteger privateExponent, @Nonnull ECPoint publicPoint) {
        this(privateExponent, publicPoint, true);
    }

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
    BouncyCastleECSigner(BigInteger privateExponent, ECPoint publicPoint, boolean canonicalize) {
        this.privateExponent = privateExponent;
        this.publicPoint = publicPoint;
        this.canonicalize = canonicalize;
    }

    /**
     * Obtain a signer given a private key - specifically a BouncyCastleECKeyPair.
     *
     * @param privateKey
     *         Key instance to collect data for signing from.
     * @return
     *         ECDSA instance capable of signature and verification.
     */
    static BouncyCastleECSigner fromPrivateKey(@Nonnull ECKey privateKey) {
        Verify.verifyNotNull(privateKey);
        assert (privateKey instanceof BouncyCastleECKeyPair);
        ECPoint publicPoint = CURVE.getCurve().decodePoint(privateKey.exportPublic());
        BigInteger privateExponent = ((BouncyCastleECKeyPair)privateKey).getPrivateExponent();
        return new BouncyCastleECSigner(privateExponent, publicPoint);
    }

    /**
     * Obtain a signer given any public key.
     *
     * @param publicKey
     *         Key instance to collect data for verification from.
     * @return
     *         ECDSA instance capable of verification.
     */
    static BouncyCastleECSigner fromPublicKey(@Nonnull ECKey publicKey) {
        Verify.verifyNotNull(publicKey);
        ECPoint publicPoint = CURVE.getCurve().decodePoint(publicKey.exportPublic());
        return new BouncyCastleECSigner(null, publicPoint);
    }

    /**
     * Obtain an ECDSA instance with the given canonicalization bit set.
     *
     * @param canonicalize
     *         If true, then the signature point is canonicalized.
     * @return
     *         ECDSA instance with canonicalization set to the given value.
     */
    BouncyCastleECSigner withCanonicalize(boolean canonicalize) {
        if (this.canonicalize == canonicalize) {
            return this;
        }
        return new BouncyCastleECSigner(privateExponent, publicPoint, canonicalize);
    }

    /**
     * Perform an ECDSA signature using the private key.
     *
     * @param hash
     *         byte array to sign.
     *
     * @return ASN.1 representation of the signature.
     */
    @Nonnull
    @Override
    public byte[] sign(@Nonnull byte[] hash) {
        if (null == privateExponent) {
            throw new UnsupportedOperationException("Cannot sign with public key");
        }
        /* The HMacDSAKCalculator is what makes this signer RFC 6979 compliant. */
        ECDSASigner signer = new ECDSASigner(new RFC6979KCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(privateExponent, DOMAIN));
        BigInteger[] signature = signer.generateSignature(hash);
        /* Need to canonicalize signature up front ... */
        if (canonicalize && signature[1].compareTo(HALF_CURVE_ORDER) > 0) {
            /* BOP does not do this */
            signature[1] = CURVE.getN().subtract(signature[1]);
        }
        try {
            return calculateSignature(signature);
        } catch (IOException e) {
            throw new IllegalStateException("IOException should not be thrown", e);
        }
    }

    /**
     * Convert the DSA signature-parts into a byte array.
     * <p>pkg protection to permit overriding in a Mock.</p>
     * @param signature
     *          ECDSA signature to convert.
     * @return
     *          byte[] for of signature.
     */
    byte[] calculateSignature(BigInteger[] signature) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        DERSequenceGenerator seq = new DERSequenceGenerator(stream);
        seq.addObject(new ASN1Integer(signature[0]));
        seq.addObject(new ASN1Integer(signature[1]));
        seq.close();
        return stream.toByteArray();
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
    @Override
    public boolean verify(@Nonnull byte[] hash, @Nonnull byte[] signature) {
        ASN1InputStream asn1 = new ASN1InputStream(signature);
        try {
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, new ECPublicKeyParameters(publicPoint, DOMAIN));
            DLSequence seq = (DLSequence) asn1.readObject();
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
            return signer.verifySignature(hash, r, s);
        } catch (Exception e) {
            // treat format errors as invalid signatures
            return false;
        } finally {
            Closeables.closeQuietly(asn1);
        }
    }

}
