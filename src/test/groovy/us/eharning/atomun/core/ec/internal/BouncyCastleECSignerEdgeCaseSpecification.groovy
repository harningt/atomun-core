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

package us.eharning.atomun.core.ec.internal

import spock.lang.Specification
import us.eharning.atomun.core.ec.ECDSA
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.ec.ECKeyFactory

import java.security.SecureRandom

/**
 * Tests for the BouncyCastleECSigner edge cases.
 */
class BouncyCastleECSignerEdgeCaseSpecification extends Specification {
    static Random random = new SecureRandom()

    def "getting a signer from a BCKP subclass passes"() {
        given: "an EC keypair that meets rules, but is a subclass"
        def privateKey = new BouncyCastleECKeyPair(BigInteger.ONE, new byte[1], false) {}
        when:
        BouncyCastleECSigner.fromPrivateKey(privateKey);
        then:
        noExceptionThrown()
    }

    def "getting a signer from a BC PublicKey fails"() {
        given: "an EC keypair that meets rules, but is a subclass"
        def privateKey = ECKeyFactory.instance.generateRandom(false).public
        when:
        BouncyCastleECSigner.fromPrivateKey(privateKey);
        then:
        thrown(AssertionError)
    }

    def "getting a signer from a non-BC ECKey fails"() {
        given: "an EC keypair that meets rules, but is a subclass"
        def privateKey = new ECKey() {
            @Override
            byte[] exportPrivate() {
                return new byte[0]
            }
            @Override
            boolean hasPrivate() {
                return true
            }
            @Override
            byte[] exportPublic() {
                return new byte[0]
            }
            @Override
            byte[] getAddressHash() {
                return new byte[0]
            }
            @Override
            ECKey getPublic() {
                return null
            }
            @Override
            ECDSA getECDSA() {
                return null
            }
        }
        when:
        BouncyCastleECSigner.fromPrivateKey(privateKey);
        then:
        thrown(AssertionError)
    }
}