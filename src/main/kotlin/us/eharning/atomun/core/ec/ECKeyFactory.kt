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

package us.eharning.atomun.core.ec

import us.eharning.atomun.core.ValidationException
import us.eharning.atomun.core.ec.internal.BouncyCastleECKeyPair
import us.eharning.atomun.core.ec.internal.BouncyCastleECPublicKey

import java.math.BigInteger

/**
 * Key factory for ECKey instances.
 */
class ECKeyFactory
/**
 * Prevent construction.
 */
private constructor() {

    @Throws(ValidationException::class)
    fun fromWIF(wif: String): ECKey {
        return BouncyCastleECKeyPair.parseWIF(wif)
    }

    fun generateRandom(compressed: Boolean): ECKey {
        return BouncyCastleECKeyPair.createNew(compressed)
    }

    @JvmOverloads
    fun fromSecretExponent(privateExponent: BigInteger, encodedPublicKey: ByteArray? = null, compressed: Boolean): ECKey {
        return BouncyCastleECKeyPair(privateExponent, encodedPublicKey, compressed)
    }

    fun fromEncodedPublicKey(encodedPublicKey: ByteArray, compressed: Boolean): ECKey {
        return BouncyCastleECPublicKey(encodedPublicKey, compressed)
    }

    companion object {
        @JvmStatic
        val instance = ECKeyFactory()
    }
}
