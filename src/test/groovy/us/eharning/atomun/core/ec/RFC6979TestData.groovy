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

package us.eharning.atomun.core.ec

import com.google.common.base.Charsets
import com.google.common.base.MoreObjects
import com.google.common.collect.ImmutableList
import com.google.common.collect.Iterables
import groovy.transform.Canonical
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequenceGenerator
import org.bouncycastle.util.BigIntegers
import org.yaml.snakeyaml.Yaml
import us.eharning.atomun.core.utility.Hash

/**
 * Test data handling for RFC6979 test cases.
 */
public class RFC6979TestData {
    @Canonical
    public static class TestCase {
        public String source;
        public String description;
        public Boolean canonicalize = null;
        public BigInteger secexp;
        public void setSecexp(String text) {
            secexp = BigIntegers.fromUnsignedByteArray(text.decodeHex())
        }
        public void setSecexp(BigInteger bi) {
            secexp = bi
        }
        public String wif;
        private byte[] messageHash;
        public void setHash(String hash) {
            if (null == description) {
                description = hash
            }
            messageHash = hash.decodeHex()
        }
        public void setHashRaw(String raw) {
            if (null == description) {
                description = raw
            }
            messageHash = raw.getBytes(Charsets.UTF_8)
        }
        public void setMessage(String message) {
            if (null == description) {
                description = message
            }
            messageHash = Hash.hash(message.getBytes(Charsets.UTF_8))
        }
        public String expectedSignature;
        public void setRsHex(String rsHex) {
            /* Decode compact signature */
            byte[] rs = rsHex.decodeHex()
            BigInteger r = BigIntegers.fromUnsignedByteArray(rs, 0, 32)
            BigInteger s = BigIntegers.fromUnsignedByteArray(rs, 32, 32)
            try {
                ByteArrayOutputStream stream = new ByteArrayOutputStream()
                DERSequenceGenerator seq = new DERSequenceGenerator(stream);
                seq.addObject(new ASN1Integer(r));
                seq.addObject(new ASN1Integer(s));
                seq.close();
                expectedSignature = stream.toByteArray().encodeHex()
            } catch (IOException e) {
                throw new IllegalStateException("IOException should not be thrown", e);
            }
        }
        public Iterable<BigInteger> expectedKList;
        public setExpectedK(BigInteger k) {
            expectedKList = [ k ]
        }
        public setExpectedKList(Iterable<Object> kList) {
            expectedKList = kList.collect({
                if (it instanceof BigInteger) {
                    return it
                } else if (it instanceof String) {
                    return new BigInteger(1, it.decodeHex())
                }
            })
        }
        public ECKey getKey() {
            if (null != wif && null != secexp) {
                BigInteger wifSecretExponent = BigIntegers.fromUnsignedByteArray(ECKeyFactory.instance.fromWIF(wif).exportPrivate())
                assert(wifSecretExponent == secexp)
            }
            if (null != wif) {
                return ECKeyFactory.instance.fromWIF(wif);
            }
            if (null != secexp) {
                /* Whether the key is compressed or not does not have an effect in signature generation */
                return ECKeyFactory.instance.fromSecretExponent(secexp, false)
            }
            throw new IllegalStateException("Missing key to use");
        }
        public boolean canTestSigning() {
            return (null != secexp || null != wif) &&
                    (null != messageHash) &&
                    (null != expectedSignature);
        }
        public boolean canTestKGeneration() {
            return (null != secexp || null != wif) &&
                    null != expectedKList && !Iterables.isEmpty(expectedKList) &&
                    (null != messageHash);
        }

        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("secexp", secexp)
                    .add("wif", wif)
                    .add("messageHash", messageHash)
                    .add("expectedSignature", expectedSignature)
                    .add("expectedKList", expectedKList)
                    .toString();
        }
    }

    public static final Iterable<TestCase> ALL_CASES;
    public static final Iterable<TestCase> K_GENERATOR_CASES;
    public static final Iterable<TestCase> SIGNATURE_CASES;

    static {
        ALL_CASES = parseBulkYAMLResource("us/eharning/atomun/core/ec/RFC6979-cases.yaml")
        SIGNATURE_CASES = Iterables.filter(ALL_CASES, {
            return it.canTestSigning()
        })
        K_GENERATOR_CASES = Iterables.filter(ALL_CASES, {
            return it.canTestKGeneration()
        })
    }

    static Iterable<TestCase> parseBulkYAMLResource(String resourceName) {
        Yaml yaml = new Yaml()
        ImmutableList.Builder<TestCase> caseBuilder = ImmutableList.builder();
        yaml.loadAll(RFC6979TestData.class.classLoader.getResourceAsStream(resourceName)).collect {
            /* For each element in the chunk, yield the related test case with the group label */
            String source = it.source
            boolean canonicalize = !!it.canonicalize
            if (!it.skip) {
                it.cases.each {
                    TestCase testCase = it as TestCase
                    testCase.source = source
                    if (testCase.canonicalize == null) {
                        testCase.canonicalize = canonicalize
                    }
                    caseList.add(testCase)
                }
            }
        }
        return caseBuilder.build()
    }
}
