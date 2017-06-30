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

package us.eharning.atomun.core.encoding;

import us.eharning.atomun.core.ValidationException;
import us.eharning.atomun.core.annotations.Beta;
import us.eharning.atomun.core.utility.Hash;

import java.util.Arrays;

/**
 * Utility class to perform Base58 transformations.
 */
@Beta
public final class Base58 {
    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final char ENCODED_ZERO = ALPHABET[0];
    private static final int[] INDEXES = new int[128];

    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    /**
     * Prevent construction as this is a static utility class.
     */
    private Base58() {
    }

    /**
     * Encode the data directly to Base58.
     *
     * @param data
     *         bytes to encode.
     *
     * @return base58-encoded string.
     */
    public static String encode(byte[] data) {
        return performEncode(data);
    }

    /**
     * Encode the data to Base58 with a prefixed 4-byte checksum using SHA-256.
     *
     * @param data
     *         bytes to encode.
     *
     * @return Base58+checksum-encoded string.
     */
    public static String encodeWithChecksum(byte[] data) {
        byte[] cs = Hash.doubleHash(data);
        byte[] extended = new byte[data.length + 4];
        System.arraycopy(data, 0, extended, 0, data.length);
        System.arraycopy(cs, 0, extended, data.length, 4);
        return performEncode(extended);
    }

    /**
     * Decode a Base58-encoded string.
     *
     * @param base58
     *         Base58-encoded string.
     *
     * @return bytes represented by string.
     */
    public static byte[] decode(String base58) {
        return performDecode(base58);
    }

    /**
     * Decode a Base58+checksum-encoded string, verifying and stripping the 4-byte checksum.
     *
     * @param base58
     *         Base58+checksum-encoded string.
     *
     * @return bytes represented by string.
     *
     * @throws ValidationException
     *         if the data is too short or there is a checksum mismatch.
     */
    public static byte[] decodeWithChecksum(String base58) throws ValidationException {
        byte[] bytes = decode(base58);
        if (bytes.length < 4) {
            throw new ValidationException("Input string too short to contain checksum");
        }

        byte[] data = new byte[bytes.length - 4];
        /* Re-use data buffer if large enough to save digest output */
        byte[] hash;
        if (data.length >= 32) {
            hash = data;
        } else {
            hash = new byte[32];
        }
        /* Generate a digest based on the content, stripping off the checksum at the end */
        Hash.doubleHash(bytes, 0, bytes.length - 4, hash, 0, 32);
        boolean matches = true;
        for (int i = 0; i < 4; i++) {
            matches &= (bytes[bytes.length - 4 + i] == hash[i]);
        }
        if (matches) {
            System.arraycopy(bytes, 0, data, 0, bytes.length - 4);
            return data;
        }
        throw new ValidationException("Checksum mismatch");
    }


    /**
     * Divides a number, represented as an array of bytes each containing a single digit
     * in the specified base, by the given divisor. The given number is modified in-place
     * to contain the quotient, and the return value is the remainder.
     *
     * @param number
     *         the number to divide
     * @param firstDigit
     *         the index within the array of the first non-zero digit
     *         (this is used for optimization by skipping the leading zeros)
     * @param base
     *         the base in which the number's digits are represented (up to 256)
     * @param divisor
     *         the number to divide by (up to 256)
     *
     * @return the remainder of the division operation
     */
    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        // this is just long division which accounts for the base of the input digits
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }

    /**
     * Returns a representation of {@code a} as an instance of type {@code B}. If {@code a} cannot be
     * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
     *
     * @param input
     *         the instance to convert; will never be null
     *
     * @return the converted instance; <b>must not</b> be null
     */
    private static String performEncode(byte[] input) {
        if (null == input) {
            throw new NullPointerException();
        }
        if (input.length == 0) {
            return "";
        }
        // Count leading zeros.
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            ++zeros;
        }
        // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
        input = Arrays.copyOf(input, input.length); // since we modify it in-place
        char[] encoded = new char[input.length * 2]; // upper bound
        int outputStart = encoded.length;
        for (int inputStart = zeros; inputStart < input.length; ) {
            encoded[--outputStart] = ALPHABET[divmod(input, inputStart, 256, 58)];
            if (input[inputStart] == 0) {
                ++inputStart; // optimization - skip leading zeros
            }
        }
            /* NOTE: Cannot seem to find a case where this executes.
             * May have to pull in more test vectors to reproduce. */
        // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
        while (outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) {
            ++outputStart;
        }
        while (--zeros >= 0) {
            encoded[--outputStart] = ENCODED_ZERO;
        }
        // Return encoded string (including encoded leading zeros).
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    /**
     * Returns a representation of {@code b} as an instance of type {@code A}. If {@code b} cannot be
     * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
     *
     * @param input
     *         the instance to convert; will never be null
     *
     * @return the converted instance; <b>must not</b> be null
     */
    private static byte[] performDecode(String input) {
        if (null == input) {
            throw new NullPointerException();
        }
        if (input.length() == 0) {
            return new byte[0];
        }
        byte[] decoded = new byte[input.length()];
        Arrays.fill(decoded, (byte) 4);
        int decodedLength = decodeToBuffer(input, decoded);
            /* If it is an exact size match, then don't re-allocate */
        if (decodedLength == decoded.length) {
            return decoded;
        }
        return Arrays.copyOf(decoded, decodedLength);
    }

    /**
     * Returns a representation of {@code b} as an instance of type {@code A}. If {@code b} cannot be
     * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
     *
     * @param input
     *         the instance to convert; will never be null
     *
     * @return the converted instance; <b>must not</b> be null
     */
    private static int decodeToBuffer(String input, byte[] decoded) {
        if (null == input || null == decoded) {
            throw new NullPointerException();
        }
        if (decoded.length < input.length()) {
            throw new IllegalArgumentException("buffer too small");
        }
        if (input.length() == 0) {
            return 0;
        }
        // Convert the base58-encoded ASCII chars to a base58 byte sequence (base58 digits).
        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); ++i) {
            char inputChar = input.charAt(i);
            int digit = inputChar < 128 ? INDEXES[inputChar] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException("Illegal character " + inputChar + " at position " + i);
            }
            input58[i] = (byte) digit;
        }
        // Count leading zeros.
        int zeros = 0;
        while (zeros < input58.length && input58[zeros] == 0) {
            ++zeros;
        }
        // Convert base-58 digits to base-256 digits.
        int outputStart = decoded.length;
        for (int inputStart = zeros; inputStart < input58.length; ) {
            decoded[--outputStart] = divmod(input58, inputStart, 58, 256);
            if (input58[inputStart] == 0) {
                ++inputStart; // optimization - skip leading zeros
            }
        }
        // Ignore extra leading zeroes that were added during the calculation.
        while (outputStart < decoded.length && decoded[outputStart] == 0) {
            ++outputStart;
        }
            /* Move the data to the front */
        int outputLength = decoded.length - outputStart;
            /* Fill in zeroes */
        Arrays.fill(decoded, 0, zeros, (byte) 0);
            /* Copy over data */
        System.arraycopy(decoded, outputStart, decoded, zeros, outputLength);
        return outputLength + zeros;
    }
}
