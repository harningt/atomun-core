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

package us.eharning.atomun.core.crypto

import com.google.common.collect.Iterables
import com.google.common.hash.HashFunction
import com.google.common.hash.Hashing
import spock.lang.Ignore
import spock.lang.Specification
import spock.lang.Unroll
import us.eharning.atomun.core.crypto.PBKDF2VectorTestData.TestCase

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
    def 'FAST PBKDF2 with #param.alg, password #param.password, salt #param.salt, iterations #param.c, and outputLength #param.dkLen'(TestCase param) {
        given:
        def dk = PBKDF2.pbkdf2(param.alg, param.passwordBytes, param.saltBytes, param.c, param.dkLen)
        expect:
        dk.encodeHex().toString() == param.dk.encodeHex().toString()
        where:
        param << Iterables.filter(PBKDF2VectorTestData.ALL_CASES, { p ->
            return !p.slow
        })
    }
    @Ignore
    @Unroll
    def 'SLOW PBKDF2 with #param.alg, password #param.password, salt #param.salt, iterations #param.c, and outputLength #param.dkLen'(TestCase param) {
        given:
        def dk = PBKDF2.pbkdf2(param.alg, param.passwordBytes, param.saltBytes, param.c, param.dkLen)
        expect:
        dk.encodeHex().toString() == param.dk.encodeHex().toString()
        where:
        param << Iterables.filter(PBKDF2VectorTestData.ALL_CASES, { p ->
            return p.slow
        })
    }

    @Unroll
    def 'FAST PBKDF2 w/ HashFunction with #param.alg, password #param.password, salt #param.salt, iterations #param.c, and outputLength #param.dkLen'(TestCase param) {
        given:
        def mac = getMac(param)
        byte[] dk = new byte[param.dkLen]
        PBKDF2.pbkdf2(mac, param.saltBytes, param.c, dk, param.dkLen)
        expect:
        dk.encodeHex().toString() == param.dk.encodeHex().toString()
        where:
        param << Iterables.filter(PBKDF2VectorTestData.ALL_CASES, { p ->
            return !p.slow
        })
    }
    @Ignore
    @Unroll
    def 'SLOW PBKDF2 w/ HashFunction with #param.alg, password #param.password, salt #param.salt, iterations #param.c, and outputLength #param.dkLen'(TestCase param) {
        given:
        def mac = getMac(param)
        byte[] dk = new byte[param.dkLen]
        PBKDF2.pbkdf2(mac, param.saltBytes, param.c, dk, param.dkLen)
        expect:
        dk.encodeHex().toString() == param.dk.encodeHex().toString()
        where:
        param << Iterables.filter(PBKDF2VectorTestData.ALL_CASES, { p ->
            return p.slow
        })
    }

    HashFunction getMac(TestCase testCase) {
        switch(testCase.alg.toLowerCase()) {
        case "hmacsha1":
            return Hashing.hmacSha1(testCase.passwordBytes)
        case "hmacsha256":
            return Hashing.hmacSha256(testCase.passwordBytes)
        case "hmacsha512":
            return Hashing.hmacSha512(testCase.passwordBytes)
        default:
            throw new UnsupportedOperationException("Alg not supported " + testCase.alg)
        }
    }
}
