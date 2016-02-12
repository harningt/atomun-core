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

package us.eharning.atomun.core.ec.internal;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import us.eharning.atomun.core.ValidationException;
import us.eharning.atomun.core.ec.ECDSA;
import us.eharning.atomun.core.ec.ECKey;
import us.eharning.atomun.core.encoding.Base58;

import java.math.BigInteger;
import java.util.Arrays;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * ECKey implementation wrapping a full keypair using BouncyCastle.
 */
@Immutable
public class BouncyCastleECKeyPair extends BouncyCastleECPublicKey {
    @Nonnull
    private final BigInteger privateExponent;

    /**
     * Construct a new EC keypair given the private exponent and whether or not to use compressed point form.
     *
     * @param privateExponent
     *         value defining the private key.
     * @param compressed
     *         whether or not to use compressed point form.
     */
    public BouncyCastleECKeyPair(@Nonnull BigInteger privateExponent, boolean compressed) {
        this(privateExponent, BouncyCastleECKeyConstants.CURVE.getG().multiply(privateExponent).getEncoded(compressed), compressed);
    }

    /**
     * Construct a new EC keypair given the private exponent, its public point, and whether or not to use compressed point form.
     *
     * @param privateExponent
     *         value defining the private key.
     * @param encodedPublicKey
     *         DER-encoded public point associated with the given private key.
     * @param compressed
     *         whether or not to use compressed point form.
     */
    public BouncyCastleECKeyPair(@Nonnull BigInteger privateExponent, @Nonnull byte[] encodedPublicKey, boolean compressed) {
        super(encodedPublicKey, compressed);
        Preconditions.checkNotNull(privateExponent);
        this.privateExponent = privateExponent;
    }

    /**
     * Utility method to create a new random EC keypair.
     *
     * @param compressed
     *         whether or not to use compressed point form.
     *
     * @return random EC keypair.
     */
    @Nonnull
    public static BouncyCastleECKeyPair createNew(boolean compressed) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(BouncyCastleECKeyConstants.DOMAIN, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();

        return new BouncyCastleECKeyPair(privParams.getD(), pubParams.getQ().getEncoded(compressed), compressed);
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
    @Nonnull
    public static BouncyCastleECKeyPair importSerialized(@Nonnull byte[] serializedPrivateExponent, boolean compressed) throws ValidationException {
        Preconditions.checkNotNull(serializedPrivateExponent);
        if (serializedPrivateExponent.length != 32) {
            throw new ValidationException("Invalid private key");
        }
        return new BouncyCastleECKeyPair(new BigInteger(1, serializedPrivateExponent).mod(BouncyCastleECKeyConstants.CURVE.getN()), compressed);
    }

    /**
     * Serialize the EC keypair in WIF Base58-encoded form.
     *
     * @param key
     *         instance to seralize.
     *
     * @return serialized EC keypair.
     */
    @Nonnull
    public static String serializeWIF(@Nonnull BouncyCastleECKeyPair key) {
        return Base58.encodeWithChecksum(bytesWIF(key));
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
    @Nonnull
    private static byte[] bytesWIF(@Nonnull BouncyCastleECKeyPair key) {
        byte[] k = key.exportPrivate();
        if (key.compressed) {
            final byte[] ek = new byte[k.length + 2];
            ek[0] = (byte) 0x80;
            System.arraycopy(k, 0, ek, 1, k.length);
            ek[k.length + 1] = 0x01;
            return ek;
        } else {
            final byte[] ek = new byte[k.length + 1];
            ek[0] = (byte) 0x80;
            System.arraycopy(k, 0, ek, 1, k.length);
            return ek;
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
    @Nonnull
    public static BouncyCastleECKeyPair parseWIF(@Nonnull String serialized) throws ValidationException {
        byte[] store = Base58.decodeWithChecksum(serialized);
        return parseBytesWIF(store);
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
    @Nonnull
    public static BouncyCastleECKeyPair parseBytesWIF(@Nonnull byte[] store) throws ValidationException {
        if (store.length == 33) {
            byte[] key = new byte[store.length - 1];
            System.arraycopy(store, 1, key, 0, store.length - 1);
            return importSerialized(key, false);
        } else if (store.length == 34) {
            byte[] key = new byte[store.length - 2];
            System.arraycopy(store, 1, key, 0, store.length - 2);
            return importSerialized(key, true);
        }
        throw new ValidationException("Invalid key length");
    }

    /**
     * Export the private key in bitcoin 'standard' form - exactly 32-bytes.
     *
     * @return exported 32-byte private key.
     */
    @Nonnull
    @Override
    public byte[] exportPrivate() {
        byte[] privateBytes = privateExponent.toByteArray();
        if (privateBytes.length != 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(privateBytes, Math.max(0, privateBytes.length - 32), tmp, Math.max(0, 32 - privateBytes.length), Math.min(32, privateBytes.length));
            privateBytes = tmp;
        }
        return privateBytes;
    }

    /**
     * Returns whether or not this keypair is populated with the private key.
     *
     * @return true - the private key is present.
     */
    @Override
    public boolean hasPrivate() {
        return true;
    }

    /**
     * Obtain a reference to this key, just including public pieces.
     *
     * @return instance with just public data present.
     */
    @Nonnull
    @Override
    public ECKey getPublic() {
        return new BouncyCastleECPublicKey(encodedPublicKey, compressed);
    }

    /**
     * Obtain a reference to the ECDSA operator for this key.
     *
     * @return instance with appropriate ECDSA capabilities.
     */
    @Nonnull
    @Override
    public ECDSA getECDSA() {
        return BouncyCastleECSigner.fromPrivateKey(this);
    }

    /**
     * Obtain an internal reference to the secret exponent.
     *
     * @return secret exponent.
     */
    @Nonnull
    BigInteger getPrivateExponent() {
        return privateExponent;
    }

    /**
     * Convert this instance to a string form - which happens to be the serialized WIF form.
     *
     * @return display string.
     */
    @Override
    public String toString() {
        return serializeWIF(this);
    }

    /**
     * Return true if this is equivalent to the passed in object (same type and same properties).
     *
     * @param obj
     *         instance to compare against.
     *
     * @return true if the values are equivalent, else false.
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        BouncyCastleECKeyPair that = (BouncyCastleECKeyPair) obj;
        return Objects.equal(compressed, that.compressed)
                && Arrays.equals(encodedPublicKey, that.encodedPublicKey)
                && Objects.equal(privateExponent, that.privateExponent);
    }

    /**
     * Returns a hash code value for the object.
     *
     * @return a hash code value for this object.
     */
    @Override
    public int hashCode() {
        return Objects.hashCode(compressed, Arrays.hashCode(encodedPublicKey), privateExponent);
    }
}
