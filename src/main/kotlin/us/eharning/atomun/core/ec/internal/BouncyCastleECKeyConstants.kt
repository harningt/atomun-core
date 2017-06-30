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

package us.eharning.atomun.core.ec.internal

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.params.ECDomainParameters

/**
 * Utility class to store constants related to ECKeys used in Bitcoin.
 */
internal object BouncyCastleECKeyConstants {
    @JvmField
    val CURVE = SECNamedCurves.getByName("secp256k1")!!
    @JvmField
    val DOMAIN = ECDomainParameters(CURVE.curve, CURVE.g, CURVE.n, CURVE.h)
}
