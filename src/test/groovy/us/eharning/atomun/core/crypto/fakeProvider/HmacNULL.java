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

package us.eharning.atomun.core.crypto.fakeProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;

/**
 * Fake HMAC that has no output length.
 */
@SuppressWarnings("unused")
public class HmacNULL extends MacSpi {
    @Override
    protected int engineGetMacLength() {
        return 0;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("HmacNULL cannot engineInit");
    }

    @Override
    protected void engineUpdate(byte b) {
        throw new UnsupportedOperationException("HmacNULL cannot engineUpdate");
    }

    @Override
    protected void engineUpdate(byte[] bytes, int i, int i1) {
        throw new UnsupportedOperationException("HmacNULL cannot engineUpdate");
    }

    @Override
    protected byte[] engineDoFinal() {
        throw new UnsupportedOperationException("HmacNULL cannot engineDoFinal");
    }

    @Override
    protected void engineReset() {
        throw new UnsupportedOperationException("HmacNULL cannot engineReset");
    }
}
