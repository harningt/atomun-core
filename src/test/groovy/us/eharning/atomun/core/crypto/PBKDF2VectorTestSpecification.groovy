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

import com.google.common.collect.Iterables
import spock.lang.Ignore
import spock.lang.Specification
import spock.lang.Unroll
import us.eharning.atomun.core.crypto.PBKDF2VectorTestData.PBKDF2VectorTestCase

/**
 * Unit tests based on test vectors for PBKDF2.
 * <p>
 * Test vectors come from:
 * <ul>
 *     <li>RFC6070 for PBKDF2-HMAC-SHA1</li>
 *     <li>
 * </p>
 */
class PBKDF2VectorTestSpecification extends Specification {
    @Unroll
    def 'FAST PBKDF2 with #param.algorithm, password #param.password, salt #param.salt, iterations #param.c, and outputLength #param.dkLen'(PBKDF2VectorTestCase param) {
        given:
        def dk = PBKDF2.pbkdf2(param.algorithm, param.password, param.salt, param.c, param.dkLen)
        expect:
        dk.encodeHex().toString() == param.dk.encodeHex().toString()
        where:
        param << Iterables.filter(PBKDF2VectorTestData.ALL_CASES, { p ->
            return !p.slow
        })
    }
    @Ignore
    @Unroll
    def 'SLOW PBKDF2 with #param.algorithm, password #param.password, salt #param.salt, iterations #param.c, and outputLength #param.dkLen'(PBKDF2VectorTestCase param) {
        given:
        def dk = PBKDF2.pbkdf2(param.algorithm, param.password, param.salt, param.c, param.dkLen)
        expect:
        dk.encodeHex().toString() == param.dk.encodeHex().toString()
        where:
        param << Iterables.filter(PBKDF2VectorTestData.ALL_CASES, { p ->
            return p.slow
        })
    }
}
