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

package us.eharning.atomun.core.crypto

import net.trajano.commons.testing.UtilityClassTestUtil
import spock.lang.Specification
import us.eharning.atomun.core.crypto.fakeProvider.FakeProvider
import us.eharning.atomun.core.crypto.fakeProvider.MacUtility

import javax.crypto.Mac
import java.security.Provider

/**
 * Unit tests based on PBKDF2 specific limitations.
 * Details come from RFC2898 - PKCS#5 Password-Based Cryptography Specification.
 */
class PBKDF2EdgeCaseSpecification extends Specification {
    /* NOTE: Cannot test (2^32 - 1) * hLen limit due to signed integer output.
     * So technically it is an impossible scenario. */

    def 'PBKDF2 fails horribly if length requirement fails'() {
        given:
        Provider provider = new FakeProvider()
        def mac = MacUtility.getInstance("HmacNULL", provider)
        byte[] EMPTY_SALT = new byte[0]
        int iterations = 1
        int outputLength = 1
        byte[] output = new byte[outputLength]
        when:
        PBKDF2.pbkdf2(mac, EMPTY_SALT, iterations, output, outputLength)
        then:
        thrown(AssertionError)
    }

    def 'PBKDF2 fails if output key length > output array'() {
        given:
        def mac = Mac.getInstance("HMACSHA1")
        byte[] EMPTY_SALT = new byte[0]
        int iterations = 1
        int outputLength = 1
        byte[] output = new byte[outputLength - 1]
        when:
        PBKDF2.pbkdf2(mac, EMPTY_SALT, iterations, output, outputLength)
        then:
        thrown(IllegalArgumentException)
    }

    def 'PBKDF2 is a utility class'() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(PBKDF2.class)
        then:
        noExceptionThrown()
    }
}
