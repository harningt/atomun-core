/*
 * Copyright 2017 Thomas Harning Jr. <harningt@gmail.com>
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

@file:Internal

package okio

import us.eharning.atomun.core.annotations.Internal
import java.math.BigInteger

/*
 * Some utility extension functions to reduce byte array copy overhead
 */

/**
 * Convert this instance into a big integer.
 *
 * @param signum
 *         -1 for negative, 0 for zero, 1 for positive).
 *
 * @return
 *         instance of BigInteger from the contained data.
 */
fun ByteString.toBigInteger(signum: Int): BigInteger {
    return this.processInternal {
        BigInteger(signum, it)
    }
}

/**
 * Copies the contents of this instance to the given byte array.
 *
 * @param output
 *         target byte array to write to
 * @param index
 *         starting point inside output to write to
 *         - defaulting to 0
 * @param length
 *         number of bytes to copy from the source into the output
 *         - defaulting to all the data
 */
fun ByteString.copyTo(output: ByteArray, index: Int = 0, length: Int = size()) {
    processInternal {
        System.arraycopy(it, 0, output, index, length)
    }
}

/**
 * Process the byte string using the provided processor.
 *
 * The processor MUST honor the contract that the data is immutable!
 *
 * @param processor callback that transforms the data into an object
 */
fun <T> ByteString.process(processor: (ByteArray) -> T): T = processInternal(processor)

/**
 * Process the byte string using the provided processor.
 *
 * The processor MUST honor the contract that the data is immutable!
 *
 * @param processor callback that transforms the data into an object
 */
private inline fun <T> ByteString.processInternal(processor: (ByteArray) -> T): T {
    val byteArray = this.internalArray() ?: toByteArray()
    return processor(byteArray)
}

class ByteStrings {
    companion object {
        /**
         * Create a ByteString, taking ownership of the provided input byte array.
         *
         * NOTE: MUST not use input after this point, else the contracts will be broken.
         */
        fun takeOwnership(input: ByteArray): ByteString = ByteString(input)
    }
}
