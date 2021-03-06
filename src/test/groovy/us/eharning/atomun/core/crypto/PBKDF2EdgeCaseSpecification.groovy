/*
 * Copyright 2016, 2019 Thomas Harning Jr. <harningt@gmail.com>
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
import us.eharning.atomun.core.crypto.fakeprovider.FakeProvider
import us.eharning.atomun.core.crypto.fakeprovider.MacUtility

import javax.crypto.Mac
import java.security.Provider
import java.security.Security

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
        Mac mac
        /* Check if using JDK9 or higher - which allows custom algorithms through */
        if (getJavaVersion() >= 9) {
            Security.addProvider(provider)
            mac = Mac.getInstance("HmacNULL", provider)
        } else {
            mac = MacUtility.getInstance("HmacNULL", provider)
        }
        byte[] EMPTY_SALT = new byte[0]
        int iterations = 1
        int outputLength = 1
        byte[] output = new byte[outputLength]
        when:
        PBKDF2.pbkdf2(mac, EMPTY_SALT, iterations, output, outputLength)
        then:
        thrown(AssertionError)
    }

    def 'PBKDF2 fails if output key length == 0'() {
        given:
        def mac = Mac.getInstance("HMACSHA1")
        byte[] EMPTY_SALT = new byte[0]
        int iterations = 1
        int outputLength = 0
        byte[] output = new byte[0]
        when:
        PBKDF2.pbkdf2(mac, EMPTY_SALT, iterations, output, outputLength)
        then:
        thrown(IllegalArgumentException)
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

    /**
     * Returns the Java version as an int value.
     * @return the Java version as an int value (8, 9, etc.)
     */
    private static int getJavaVersion() {
        String version = System.getProperty("java.version");
        if (version.startsWith("1.")) {
            version = version.substring(2);
        }
        int dotPos = version.indexOf('.');
        int dashPos = version.indexOf('-');
        return Integer.parseInt(version.substring(0,
                dotPos > -1 ? dotPos : dashPos > -1 ? dashPos : 1));
    }
}
