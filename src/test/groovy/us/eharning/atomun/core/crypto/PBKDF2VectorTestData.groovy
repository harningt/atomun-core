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
import groovy.transform.AutoClone
import groovy.transform.Canonical
import org.yaml.snakeyaml.Yaml

/**
 * Container for common PBKDF2 vector test data.
 */
class PBKDF2VectorTestData {
    @Canonical
    @AutoClone
    static class TestCase {
        String alg;
        String password;

        String salt;

        int c;
        int dkLen;
        byte[] dk;
        public void setDK(String dk) {
            this.dk = dk.replace(" ", "").decodeHex();
        }
        boolean slow;

        byte[] getPasswordBytes() {
            return password.getBytes(Charsets.UTF_8)
        }
        byte[] getSaltBytes() {
            return salt.getBytes(Charsets.UTF_8)
        }
    }

    public static final Iterable<TestCase> ALL_CASES;

    static {
        ALL_CASES = parseYamlResource("us/eharning/atomun/core/crypto/rfc6070-cases.yaml")
    }

    static List<TestCase> parseYamlResource(String resourceName) {
        Yaml yaml = new Yaml()
        ImmutableList.Builder<TestCase> caseBuilder = ImmutableList.builder();
        yaml.loadAll(PBKDF2VectorTestData.class.classLoader.getResourceAsStream(resourceName)).each {
            String alg = it.alg
            if (it.skip) {
                return
            }
            it.cases.each {
                TestCase testCase = it as TestCase
                if (!testCase.alg) {
                    testCase.alg = alg
                }
                caseBuilder.add(testCase)
            }
        }
        return caseBuilder.build()
    }
}
