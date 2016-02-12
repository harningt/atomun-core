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
import us.eharning.atomun.core.ec.ECDSA;
import us.eharning.atomun.core.ec.ECKey;
import us.eharning.atomun.core.utility.Hash;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * ECKey implementation wrapping a public key using BouncyCastle.
 */
@Immutable
public class BouncyCastleECPublicKey implements ECKey {
    protected static final SecureRandom secureRandom = new SecureRandom();

    @Nonnull
    protected final byte[] encodedPublicKey;
    protected final boolean compressed;

    /**
     * Construct a public key from the given encoded public key and whether or not to treat is as compressed.
     *
     * @param encodedPublicKey
     *         DER-encoded EC public key.
     * @param compressed
     *         whether or not the EC public key is in compressed point form.
     */
    public BouncyCastleECPublicKey(@Nonnull byte[] encodedPublicKey, boolean compressed) {
        Preconditions.checkNotNull(encodedPublicKey);
        this.encodedPublicKey = Arrays.copyOf(encodedPublicKey, encodedPublicKey.length);
        this.compressed = compressed;
    }

    /**
     * Obtain the 'address hash' per Bitcoin rules.
     *
     * @return 20-byte address hash byte array
     */
    @Nonnull
    @Override
    public byte[] getAddressHash() {
        return Hash.keyHash(encodedPublicKey);
    }

    /**
     * Export the private key in bitcoin 'standard' form - exactly 32-bytes.
     *
     * @return exported 32-byte private key or null if not present.
     */
    @CheckForNull
    @Override
    public byte[] exportPrivate() {
        return null;
    }

    /**
     * Returns whether or not this keypair is populated with the private key.
     *
     * @return false - the private key is not present.
     */
    @Override
    public boolean hasPrivate() {
        return false;
    }

    /**
     * Export the public key in ASN.1-encoded form.
     *
     * @return ASN.1 encoded public key bytes.
     */
    @Nonnull
    @Override
    public byte[] exportPublic() {
        return Arrays.copyOf(encodedPublicKey, encodedPublicKey.length);
    }

    /**
     * Obtain a reference to this key, just including public pieces.
     *
     * @return instance with just public data present.
     */
    @Nonnull
    @Override
    public ECKey getPublic() {
        return this;
    }

    /**
     * Obtain a reference to the ECDSA operator for this key.
     *
     * @return instance with appropriate ECDSA capabilities.
     */
    @Nonnull
    @Override
    public ECDSA getECDSA() {
        return BouncyCastleECSigner.fromPublicKey(this);
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
        BouncyCastleECPublicKey that = (BouncyCastleECPublicKey) obj;
        return Objects.equal(compressed, that.compressed)
                && Arrays.equals(encodedPublicKey, that.encodedPublicKey);
    }

    /**
     * Returns a hash code value for the object.
     *
     * @return a hash code value for this object.
     */
    @Override
    public int hashCode() {
        return Objects.hashCode(Arrays.hashCode(encodedPublicKey), compressed);
    }
}
