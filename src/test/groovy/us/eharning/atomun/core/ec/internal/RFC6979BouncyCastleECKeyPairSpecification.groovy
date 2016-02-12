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
import spock.lang.Unroll
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.ec.RFC6979TestData
import us.eharning.atomun.core.ec.RFC6979TestData.TestCase

/**
 * Tests for the various ECKeyPair implementations.
 */
class RFC6979BouncyCastleECKeyPairSpecification extends Specification {
    @Unroll
    def "[#iterationCount] signature-generation passes #testCase.source => #testCase.description"(TestCase testCase) {
        given:
        ECKey keyPair = testCase.key
        ECKey publicKey = keyPair.public
        byte[] toSign = testCase.messageHash
        byte[] signature = keyPair.ECDSA.withCanonicalize(testCase.canonicalize).sign(toSign);
        expect:

        publicKey.ECDSA.verify(toSign, signature)
        signature.encodeHex().toString() == testCase.expectedSignature

        where:
        testCase << RFC6979TestData.SIGNATURE_CASES
    }
}