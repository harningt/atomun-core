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

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import spock.lang.Specification
import spock.lang.Unroll
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.ec.RFC6979TestData
import us.eharning.atomun.core.ec.RFC6979TestData.TestCase

import java.security.SecureRandom

/**
 * Tests for the various RFC6979 K Calculator implementations.
 */
class RFC6979KCalculatorSpecification extends Specification {
    protected static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    protected static final ECDomainParameters domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());

    def "k-generation does not support SecureRandom being passed in"() {
        given:
        BigInteger n = BigInteger.TEN
        RFC6979KCalculator calc = new RFC6979KCalculator(new SHA256Digest());
        when:
        calc.init(n, new SecureRandom())
        then:
        thrown(IllegalStateException)
    }

    def "k-generation repeats if it would be zero in the iteration loop"() {
        given: "constants that have been found to result in the first pass generating zero"
        BigInteger q = new BigInteger(1, "06".decodeHex())
        BigInteger x = new BigInteger(1, "0A".decodeHex())
        byte[] hash = "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF".decodeHex()
        BigInteger expected = new BigInteger(1, "01".decodeHex())
        RFC6979KCalculator calc = new RFC6979KCalculator(new SHA256Digest());
        calc.init(q, x, hash)
        BigInteger nextK = calc.nextK();

        expect:
        nextK == expected
    }

    @Unroll
    def "[#iterationIndex] k-generation passes #testCase.source => #testCase.description"(TestCase testCase) {
        ECKey key = testCase.getKey()
        BigInteger secexp = new BigInteger(1, key.exportPrivate())
        ECPrivateKeyParameters keyParams = new ECPrivateKeyParameters(secexp, domain)
        given:
        byte[] toSign = testCase.messageHash
        RFC6979KCalculator calc = new RFC6979KCalculator(new SHA256Digest());
        calc.init(keyParams.getParameters().getN(), keyParams.getD(), toSign);
        expect:

        for (BigInteger expectedK: testCase.expectedKList) {
            BigInteger nextK = calc.nextK();
            assert nextK.toString(16) == expectedK.toString(16)
        }

        where:
        testCase << RFC6979TestData.K_GENERATOR_CASES
    }

    /* See: https://github.com/codahale/rfc6979/blob/ce0a68115f573236ef326cccb71a7d5ba68c9890/rfc6979_test.go */
    def "base case from go's rfc6979"() {
        given:
        BigInteger q = new BigInteger(1, "04000000000000000000020108A2E0CC0D99F8A5EF".decodeHex())
        BigInteger x = new BigInteger(1, "009A4D6792295A7F730FC3F2B49CBC0F62E862272F".decodeHex())
        byte[] hash = "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF".decodeHex()
        BigInteger expected = new BigInteger(1, "023AF4074C90A02B3FE61D286D5C87F425E6BDD81B".decodeHex())
        RFC6979KCalculator calc = new RFC6979KCalculator(new SHA256Digest());
        calc.init(q, x, hash)
        BigInteger nextK = calc.nextK();

        expect:
        nextK == expected
    }
}
