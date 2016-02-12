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

import spock.lang.Specification
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.ec.ECKeyFactory

import java.security.SecureRandom

/**
 * Tests for the various ECKeyPair implementations.
 */
class BouncyCastleECKeyPairSpecification extends Specification {
    static Random random = new SecureRandom()

    def "signature-verification passes"() {
        given:
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(false)
        ECKey publicKey = keyPair.public
        byte[] toSign = new byte[100];
        random.nextBytes (toSign);
        byte[] signature = keyPair.ECDSA.sign(toSign);
        expect:
        keyPair.public ==  publicKey.public
        keyPair.addressHash == publicKey.addressHash

        publicKey.ECDSA.verify (toSign, signature)
        where:
        [ i ] << ([0..20].iterator())
    }

    def "public key of a private key is self-equivalent"() {
        given:
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(false)
        ECKey publicKey = keyPair.public
        expect: "re-retrieved key is also equivalent"
        publicKey == keyPair.public
        and: "self key equality is also equivalent"
        publicKey == publicKey.public
    }

    def "exported public key can import and is equivalent"() {
        given:
        ECKey publicKey = ECKeyFactory.getInstance().generateRandom(false).public
        expect: "exporting public key works"
        byte[] exported = publicKey.exportPublic()
        and: "imported public key is the same as the original"
        publicKey == ECKeyFactory.instance.fromEncodedPublicKey(exported, false)
    }
}