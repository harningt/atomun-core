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

package us.eharning.atomun.core.encoding

import net.trajano.commons.testing.UtilityClassTestUtil
import spock.lang.Specification
import us.eharning.atomun.core.ValidationException

/**
 * Test cases verifying Base58 functionality.
 */
class Base58Specification extends Specification {
    def 'Base58 is a utility class'() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(Base58.class)
        then:
        noExceptionThrown()
    }
    def 'Base58 empty encoding/decoding results'() {
        expect:
        Base58.encode(new byte[0]) == ""
        Base58.decode("").length == 0
    }
    def 'Base58 empty checksum encoding/decoding results'() {
        expect:
        Base58.encodeWithChecksum(new byte[0]) == "3QJmnh"
        Base58.decodeWithChecksum("3QJmnh").length == 0
    }
    def 'Base58 with checksum fails on modification'() {
        when:
        Base58.decodeWithChecksum("3QJmnH")
        then:
        thrown(ValidationException)
    }
    def 'Base58 with checksum fails on too small data'() {
        when:
        Base58.decodeWithChecksum(input)
        then:
        thrown(ValidationException)
        where:
        _ | input
        _ | "3QJmn"
        _ |  ""
    }
    def 'Base58 handles leading zeroes by encoding them as an equal sequence of 1s'() {
        given:
        char[] characters = new char[length]
        Arrays.fill(characters, (char)'1')
        byte[] zeroes = new byte[length]
        expect:
        Base58.encode(zeroes) == String.valueOf(characters)
        Base58.decode(String.valueOf(characters)) == zeroes

        where:
        _ | length
        _ | 0
        _ | 1
        _ | 2
        _ | 3
        _ | 10
        _ | 20
    }
    def 'Base58 cases'(String binaryHex, String base58) {
        given:
        byte[] binary = binaryHex.decodeHex()
        expect:
        Base58.encode(binary) == base58
        Base58.decode(base58).encodeHex().toString() == binary.encodeHex().toString()
        where:
        binaryHex | base58
        '00000001' | '1112'
        /* Borrowed from BitcoinJ unit test for special case handling */
        'Hello World'.bytes.encodeHex() | 'JxF12TrwUP45BMd'
        'effb309e964684b54e6069f146e2cd6dae936b711a7a98df4097156b9fc9b344eb4f9a4b14' | '93VYUMzRG9DdbRP72uQXjaWibbQwygnvaCu9DumcqDjGybD864T'
        "61" | "2g"
        "626262" | "a3gV"
        "636363" | "aPEr"
        "73696d706c792061206c6f6e6720737472696e67" | "2cFupjhnEsSn59qHXstmK2ffpLv2"
        "00eb15231dfceb60925886b67d065299925915aeb172c06647" | "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"
        "516b6fcd0f" | "ABnLTmg"
        "bf4f89001e670274dd" | "3SEo3LWLoPntC"
        "572e4794" | "3EFU7m"
        "ecac89cad93923c02321" | "EJDM8drfXA6uyA"
        "10c8511e" | "Rt5zm"
    }
    def 'Base58 hates bad characters'() {
        when:
        Base58.decode('!')
        then:
        thrown(IllegalArgumentException)
    }
}
