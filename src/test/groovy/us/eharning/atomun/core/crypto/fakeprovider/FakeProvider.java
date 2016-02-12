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

import java.security.Provider;

/**
 * Fake provider with tweaked algorithms to expose odd behavior.
 */
public class FakeProvider extends Provider {
    private static final String NAME = "FakeProvider";
    private static final double VERSION = 1.0;
    private static final String INFO = "FakeProvider 1.0";

    public FakeProvider() {
        super(NAME, VERSION, INFO);
        put("Mac.HmacNULL", "us.eharning.atomun.core.crypto.fakeprovider.HmacNULL");
    }
}
