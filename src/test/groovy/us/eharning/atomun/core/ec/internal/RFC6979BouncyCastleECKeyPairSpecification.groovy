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

package us.eharning.atomun.core.ec.internal

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import spock.lang.Specification
import spock.lang.Unroll
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.ec.RFC6979TestData
import us.eharning.atomun.core.ec.RFC6979TestData.TestCase

/**
 * Tests for the various ECKeyPair implementations.
 */
class RFC6979BouncyCastleECKeyPairSpecification extends Specification {
    protected static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    protected static final ECDomainParameters domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());

    @Unroll
    def "[#iterationCount] signature-generation passes #testCase.source => #testCase.description"(TestCase testCase) {
        given:
        /* UGLY HACK TO MANIPULATE CANONICALIZATION */
        BouncyCastleECKeyPair.CANONICALIZE = testCase.canonicalize
        ECKey keyPair = testCase.key
        ECKey publicKey = keyPair.public
        byte[] toSign = testCase.messageHash
        byte[] signature = keyPair.sign (toSign);
        expect:

        publicKey.verify (toSign, signature)
        signature.encodeHex().toString() == testCase.expectedSignature

        where:
        testCase << RFC6979TestData.SIGNATURE_CASES
    }
}