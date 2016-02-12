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

package us.eharning.atomun.core.crypto.fakeprovider;

import com.google.common.base.Throwables;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import javax.annotation.Nonnull;
import javax.crypto.Mac;
import javax.crypto.MacSpi;

/**
 * Utility to force the construction of a Mac with a given SPI.
 */
public class MacUtility {
    /**
     * Utility to get a Mac instance from the named provider.
     *
     * @param algorithm
     *          name of the Mac algorithm to retrieve.
     * @param provider
     *          service provider to retrieve instance from.
     * @return
     *          Mac instance wrapping the SPI.
     * @throws NoSuchAlgorithmException if the algorithm is non-existent.
     */
    @Nonnull
    public static Mac getInstance(@Nonnull String algorithm, @Nonnull Provider provider) throws NoSuchAlgorithmException {
        MacSpi spi = (MacSpi) provider.getService("Mac", algorithm).newInstance(null);
        return getInstance(spi, algorithm, provider);
    }

    /**
     * Utility to construct a Mac instance as if it was from the named provider.
     *
     * @param spi
     *          service provider to wrap.
     * @param algorithm
     *          name of the Mac algorithm to wrap.
     * @param provider
     *          service provider to attach to the instance.
     * @return
     *          Mac instance wrapping the SPI.
     */
    @Nonnull
    public static Mac getInstance(@Nonnull MacSpi spi, @Nonnull String algorithm, @Nonnull Provider provider) {
        try {
            Constructor<Mac> constructor = Mac.class.getDeclaredConstructor(MacSpi.class, Provider.class, String.class);
            constructor.setAccessible(true);
            return constructor.newInstance(spi, provider, algorithm);
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw Throwables.propagate(e);
        }
    }
}
