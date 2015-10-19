/*
 * Copyright 2015 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.core.ec;

import us.eharning.atomun.core.ec.internal.BouncyCastleECKeyPair;
import us.eharning.atomun.core.ec.internal.BouncyCastleECPublicKey;

import java.math.BigInteger;

/**
 * Key factory for ECKey instances.
 */
public class ECKeyFactory {
    private static final ECKeyFactory INSTANCE = new ECKeyFactory();

    /**
     * Prevent construction.
     */
    private ECKeyFactory() {
    }

    public static ECKeyFactory getInstance() {
        return INSTANCE;
    }

    public ECKey generateRandom(boolean compressed) {
        return BouncyCastleECKeyPair.createNew(compressed);
    }

    public ECKey fromSecretExponent(BigInteger privateExponent, boolean compressed) {
        return new BouncyCastleECKeyPair(privateExponent, compressed);
    }

    public ECKey fromSecretExponent(BigInteger privateExponent, byte[] encodedPublicKey, boolean compressed) {
        return new BouncyCastleECKeyPair(privateExponent, encodedPublicKey, compressed);
    }

    public ECKey fromEncodedPublicKey(byte[] encodedPublicKey, boolean compressed) {
        return new BouncyCastleECPublicKey(encodedPublicKey, compressed);
    }
}
