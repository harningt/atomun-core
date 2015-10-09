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

package us.eharning.atomun.core.crypto

import com.google.common.base.Charsets
import com.google.common.collect.ImmutableList
import com.google.common.collect.Iterables
import groovy.json.StringEscapeUtils
import groovy.transform.AutoClone

/**
 * Container for common PBKDF2 vector test data.
 */
class PBKDF2VectorTestData {
    @AutoClone
    static class PBKDF2VectorTestCase {
        String algorithm;
        byte[] password;
        byte[] salt;

        int c;
        int dkLen;
        byte[] dk;
        boolean slow;
    }

    public static final Iterable<PBKDF2VectorTestCase> EDGE_CASES;
    public static final Iterable<PBKDF2VectorTestCase> HMAC_SHA1_CASES;
    public static final Iterable<PBKDF2VectorTestCase> HMAC_SHA256_CASES;
    public static final Iterable<PBKDF2VectorTestCase> HMAC_SHA512_CASES;
    public static final Iterable<PBKDF2VectorTestCase> ALL_CASES;

    static {
        EDGE_CASES = parseResource("us/eharning/atomun/core/crypto/pbkdf2-edge-cases.txt")
        HMAC_SHA1_CASES = parseResource("us/eharning/atomun/core/crypto/rfc6070-cases.txt")
        HMAC_SHA256_CASES = parseResource("us/eharning/atomun/core/crypto/rfc6070-based-HMAC-SHA256-cases.txt")
        HMAC_SHA512_CASES = parseResource("us/eharning/atomun/core/crypto/rfc6070-based-HMAC-SHA512-cases.txt")
        ALL_CASES = Iterables.concat(
                EDGE_CASES,
                HMAC_SHA1_CASES,
                HMAC_SHA256_CASES,
                HMAC_SHA512_CASES
        )
    }

    static Iterable<PBKDF2VectorTestCase> parseResource(String resourceName) {
        List<PBKDF2VectorTestCase> cases = new ArrayList<>()

        PBKDF2VectorTestCase builder = new PBKDF2VectorTestCase()
        PBKDF2VectorTestData.class.classLoader.getResourceAsStream(resourceName).withReader("UTF-8", { reader ->
            reader.eachLine { line ->
                if (line.empty) {
                    return
                }
                def (name, value) = line.split(" *= *")
                name = name.toLowerCase()
                switch (name) {
                case "p":
                case "s":
                case "dk":
                    def finder = value =~ /^"(.+)"$/
                    if (finder) {
                        value = StringEscapeUtils.unescapeJava(finder[0][1])
                        value = value.getBytes(Charsets.UTF_8)
                    } else {
                        /* Byte string */
                        value = value.replace(" ", "").decodeHex()
                    }
                }
                switch (name) {
                case "alg":
                    builder.algorithm = value
                    break
                case "p":
                    builder.password = value
                    break
                case "s":
                    builder.salt = value
                    break
                case "c":
                    builder.c = Integer.parseInt(value)
                    break
                case "dklen":
                    builder.dkLen = Integer.parseInt(value)
                    break
                case "slow":
                    builder.slow = Boolean.parseBoolean(value)
                    break
                case "dk":
                    builder.dk = value
                    assert(builder.dkLen == builder.dk.length)
                    /* Also marks end of builder */
                    cases.add(builder.clone())
                    /* Resets slow marker */
                    builder.slow = false
                    break
                }
            }
        })
        return ImmutableList.copyOf(cases);
    }
}
