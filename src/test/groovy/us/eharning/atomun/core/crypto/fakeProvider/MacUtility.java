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

import com.google.common.base.Throwables;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import javax.crypto.Mac;
import javax.crypto.MacSpi;

/**
 * Utility to force the construction of a Mac with a given SPI.
 */
public class MacUtility {
    public static Mac getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        MacSpi spi = (MacSpi) provider.getService("Mac", algorithm).newInstance(null);
        return getInstance(spi, provider, algorithm);
    }
    public static Mac getInstance(MacSpi spi, Provider provider, String algorithm) {
        try {
            Constructor<Mac> constructor = Mac.class.getDeclaredConstructor(MacSpi.class, Provider.class, String.class);
            constructor.setAccessible(true);
            return constructor.newInstance(spi, provider, algorithm);
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw Throwables.propagate(e);
        }
    }
}
