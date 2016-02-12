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

package us.eharning.atomun.core

import net.trajano.commons.testing.UtilityClassTestUtil
import spock.lang.Specification
import spock.lang.Unroll
import us.eharning.atomun.core.utility.Hash

import java.security.Provider
import java.security.Security
import java.util.concurrent.Callable

/**
 * Test case specification to try to hit odd edge cases.
 */
class EdgeCaseSpecification extends Specification {
    @Unroll
    def "missing algorithm results in error on hash ops like #name"(String name, Callable<Void> op) {
        given:
        Provider[] providerBackup = Security.providers;
        for (Provider provider : Security.providers.reverse()) {
            Security.removeProvider(provider.getName())
        }
        when:
        op()
        then:
        thrown(Error)
        cleanup:
        for (Provider provider : providerBackup) {
            Security.addProvider(provider);
        }
        where:
        name | op
        "hash([])"      | { Hash.hash(new byte[0]) }
        "hash([],i,i)"  | { Hash.hash(new byte[2], 1, 1) }
        "doubleHash([])"      | { Hash.doubleHash(new byte[0]) }
        "doubleHash([],i,i)"  | { Hash.doubleHash(new byte[2], 1, 1) }
        "keyHash([])"   | { Hash.keyHash(new byte[0]) }
    }
    def 'Hash is a utility class'() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(Hash.class)
        then:
        noExceptionThrown()
    }
    def 'validationException sanity for storage'() {
        given:
        def message = "Hello"
        def cause = new Exception()
        def withCause = new ValidationException(cause)
        def withMessage = new ValidationException(message)
        def withMessageCause = new ValidationException(message, cause)
        expect:
        withCause.cause == cause
        withMessage.message == message
        withMessageCause.cause == cause
        withMessageCause.message == message
    }
}
