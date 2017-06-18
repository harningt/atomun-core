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

package us.eharning.atomun.core.ec.internal

import net.trajano.commons.testing.EqualsTestUtil
import net.trajano.commons.testing.UtilityClassTestUtil
import org.bouncycastle.math.ec.ECPoint
import spock.lang.Specification
import us.eharning.atomun.core.ValidationException
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.ec.ECKeyFactory

import java.security.SecureRandom

import static us.eharning.atomun.core.ec.internal.BouncyCastleECKeyConstants.CURVE

/**
 * Tests for the various ECKeyPair implementations.
 */
class BouncyCastleECKeyPairSpecification extends Specification {
    static Random random = new SecureRandom()

    def "BouncyCastleECKeyConstants is a utility class"() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(BouncyCastleECKeyConstants.class)
        then:
        noExceptionThrown()
    }

    def "signature-verification passes - not-compressed"() {
        given:
        boolean isCompressed = false
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        ECKey publicKey = keyPair.public
        byte[] toSign = new byte[100];
        random.nextBytes(toSign);
        byte[] signature = keyPair.ECDSA.sign(toSign);
        expect:
        keyPair.public ==  publicKey.public
        keyPair.addressHash == publicKey.addressHash
        publicKey.ECDSA.verify(toSign, signature)
        where:
        [ i ] << ([0..20].iterator())
    }

    def "signature-verification passes - compressed"() {
        given:
        boolean isCompressed = true
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        ECKey publicKey = keyPair.public
        byte[] toSign = new byte[100];
        random.nextBytes(toSign);
        byte[] signature = keyPair.ECDSA.sign(toSign);
        expect:
        keyPair.public ==  publicKey.public
        keyPair.addressHash == publicKey.addressHash

        publicKey.ECDSA.verify(toSign, signature)
        where:
        [ i ] << ([0..20].iterator())
    }

    def "signature with forced failure throws - for coverage"() {
        given:
        boolean isCompressed = true
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)

        byte[] toSign = new byte[100];
        random.nextBytes(toSign);
        ECPoint publicPoint = CURVE.getCurve().decodePoint(keyPair.exportPublic());
        BouncyCastleECSigner ecdsa = Spy(BouncyCastleECSigner.class, constructorArgs: [ keyPair.getPrivateExponent(), publicPoint ])
        ecdsa.calculateSignature(_) >> { throw new IOException("Illegal state"); }
        when:
        ecdsa.sign(toSign);
        then:
        thrown(IllegalStateException)
    }

    def "signature-verification of modified data fails"() {
        given:
        boolean isCompressed = false
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        ECKey publicKey = keyPair.public
        byte[] toSign = new byte[100];
        random.nextBytes(toSign);
        byte[] signature = keyPair.ECDSA.sign(toSign);
        random.nextBytes(toSign);
        !publicKey.ECDSA.verify(toSign, signature)
        where:
        [ i ] << ([0..20].iterator())
    }
    def "signature-verification of modified signature fails"() {
        given:
        boolean isCompressed = false
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        ECKey publicKey = keyPair.public
        byte[] toSign = new byte[100];
        random.nextBytes(toSign);
        byte[] signature = keyPair.ECDSA.sign(toSign);
        random.nextBytes(signature);
        !publicKey.ECDSA.verify(toSign, signature)
        where:
        [ i ] << ([0..20].iterator())
    }

    def "public key of a private key is self-equivalent"(boolean isCompressed) {
        given:
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        ECKey publicKey = keyPair.public
        expect: "re-retrieved key is also equivalent"
        publicKey == keyPair.public
        and: "self key equality is also equivalent"
        publicKey == publicKey.public
        and: "public/private key inequality is correct"
        keyPair != publicKey
        publicKey != keyPair
        and: "identity works"
        EqualsTestUtil.assertEqualsImplementedCorrectly(keyPair)
        EqualsTestUtil.assertEqualsImplementedCorrectly(publicKey)
        and: "toString of forms equal"
        keyPair.toString() == keyPair.toString()
        publicKey.toString() == publicKey.toString()
        publicKey.toString() == publicKey.public.toString()
        and: "bits are all set right"
        keyPair.hasPrivate()
        !publicKey.hasPrivate()
        where:
        _ | isCompressed
        _ | false
        _ | true
    }

    def "re-imported private keys are equivalent"(boolean isCompressed) {
        given: "a keypair and its imported form"
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        ECKey importedKeyPair = ECKeyFactory.getInstance().fromSecretExponent(new BigInteger(1, keyPair.exportPrivate()), isCompressed)
        expect: "them to be equal"
        EqualsTestUtil.assertEqualsImplementedCorrectly(keyPair, importedKeyPair)
        where:
        _ | isCompressed
        _ | false
        _ | true
    }

    def "re-imported public keys are equivalent"(boolean isCompressed) {
        given: "a public key and its imported form"
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        ECKey publicKey = keyPair.public
        ECKey importedPublicKey = ECKeyFactory.getInstance().fromEncodedPublicKey(publicKey.exportPublic(), isCompressed)
        expect: "them to be equal"
        EqualsTestUtil.assertEqualsImplementedCorrectly(publicKey, importedPublicKey)
        where:
        _ | isCompressed
        _ | false
        _ | true
    }

    def "fresh-generated keys are not equal"(boolean isCompressed) {
        given:
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        ECKey publicKey = keyPair.public
        expect: "newly generated keys not to be equal"
        keyPair != ECKeyFactory.instance.generateRandom(true)
        keyPair != ECKeyFactory.instance.generateRandom(false)
        publicKey != ECKeyFactory.instance.generateRandom(true).public
        publicKey != ECKeyFactory.instance.generateRandom(false).public
        where:
        _ | isCompressed
        _ | false
        _ | true
    }

    def "keys generated with altered key material are not equal"(boolean isCompressed) {
        given:
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        ECKey badImportedKeyPairPublic = ECKeyFactory.getInstance().fromSecretExponent(new BigInteger(1, keyPair.exportPrivate()), new byte[32], isCompressed)
        ECKey badImportedKeyPairPrivate = ECKeyFactory.getInstance().fromSecretExponent(new BigInteger(1, keyPair.exportPrivate()).add(BigInteger.ONE), keyPair.exportPublic(), isCompressed)
        expect: "private with mis-generated private != real private"
        keyPair != badImportedKeyPairPublic
        keyPair != badImportedKeyPairPrivate
        where:
        _ | isCompressed
        _ | false
        _ | true
    }

    def "exported public key can import and is equivalent"(boolean isCompressed) {
        given:
        ECKey publicKey = ECKeyFactory.getInstance().generateRandom(isCompressed).public
        expect: "exporting public key works"
        byte[] exported = publicKey.exportPublic()
        and: "imported public key is the same as the original"
        publicKey == ECKeyFactory.instance.fromEncodedPublicKey(exported, isCompressed)
        where:
        _ | isCompressed
        _ | false
        _ | true

    }

    def "key can be generated from components"(boolean isCompressed) {
        given:
        ECKey keyPair = ECKeyFactory.getInstance().generateRandom(isCompressed)
        byte[] exportedPrivateBytes = keyPair.exportPrivate()
        BigInteger secretExponent = new BigInteger(1, exportedPrivateBytes)
        ECKey newKeyPair = ECKeyFactory.getInstance().fromSecretExponent(secretExponent, keyPair.exportPublic(), isCompressed)
        expect: "re-retrieved key is also equivalent"
        newKeyPair == keyPair
        and: "public key portion is also equivalent"
        newKeyPair.public == keyPair.public
        and: "bits are all set right"
        newKeyPair.hasPrivate()
        newKeyPair.exportPrivate() != null
        !newKeyPair.public.hasPrivate()
        newKeyPair.public.exportPrivate() == null
        where:
        _ | isCompressed
        _ | false
        _ | true
    }

    def "signing with public key fails"() {
        given:
        ECKey publicKey = ECKeyFactory.getInstance().generateRandom(false).public
        when: "signing with public key does not work"
        publicKey.ECDSA.sign(new byte[0])
        then:
        thrown(UnsupportedOperationException)
    }

    def "key import fails with invalid wif"() {
        when: "importing key with invalid WIF"
        ECKey key = (wif instanceof String) ? BouncyCastleECKeyPair.parseWIF(wif) : BouncyCastleECKeyPair.parseBytesWIF(wif)
        then:
        thrown(ValidationException)
        where:
        _ | wif
        _ | new byte[0]
        _ | new byte[1]
        /* Valid key with mangled byte */
        _ | "L1MuYFhSGEJYXZWHRLt2Ggnou5BzCMy7165eFTB2qPPU93B4fRjV"
        /* Valid key with mangled byte */
        _ | "5HX15HFGyep2CfPxsJKe2fXJsCVn5DEiyoeGGF6JZjGbTRnqfiD"
    }

    def "key import fails with invalid serialized secret-exponent"(boolean compressed, byte[] serializedPrivateExponent) {
        when:
        BouncyCastleECKeyPair.importSerialized(serializedPrivateExponent, compressed)
        then:
        thrown(ValidationException)
        where:
        compressed | serializedPrivateExponent
        true       | new byte[0]
        true       | new byte[1]
        true       | new byte[31]
        true       | new byte[33]
        false      | new byte[0]
        false      | new byte[1]
        false      | new byte[31]
        false      | new byte[33]
    }
}
