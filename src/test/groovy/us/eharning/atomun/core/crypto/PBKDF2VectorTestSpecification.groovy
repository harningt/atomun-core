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
