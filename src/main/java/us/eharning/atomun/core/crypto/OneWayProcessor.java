package us.eharning.atomun.core.crypto;

import com.google.common.annotations.Beta;
import com.google.common.io.ByteProcessor;

import java.io.IOException;

/**
 * Mechanism to feed bytes and have a single final byte output stream w/ reset capability.
 *
 * @since 0.0.3
 */
@Beta
public interface OneWayProcessor extends ByteProcessor<byte[]> {

    /**
     * Return the size of the output buffer required for the results.
     *
     * @return size of expected output buffer in bytes.
     */
    int getOutputLength();

    /**
     * @see ByteProcessor
     * <p>Same except IOException will not be thrown</p>
     */
    @Override
    boolean processBytes(byte[] buf, int off, int len);

    /**
     * Write the results of the operation in the given buffer.
     *
     * @param output
     *          byte buffer to write to.
     * @param offset
     *          offset in to the buffer to start writing.
     * @param maxLength
     *          maximum number of bytes to write.
     *
     * @return number of bytes written.
     *
     * @throws IllegalArgumentException
     *      if the output buffer is null, too small, or max length is too small for hash.
     */
    int writeTo(byte[] output, int offset, int maxLength);

    /**
     * Reset the processor to permit re-use.
     */
    void reset();
}
