package us.eharning.atomun.core.crypto;

import com.google.common.annotations.Beta;
import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;

import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class to obtain useful processors.
 *
 * @since 0.3.0
 */
@Beta
public final class OneWayProcessors {
    static OneWayProcessor getJceHash(String algorithm) throws NoSuchAlgorithmException {
        return new JceDigestProcessor(MessageDigest.getInstance(algorithm));
    }

    static OneWayProcessor getJceMac(String algorithm, byte[] key) throws NoSuchAlgorithmException {
        Mac mac = Mac.getInstance(algorithm);
        try {
            mac.init(new SecretKeySpec(key, algorithm));
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }

        return wrapJceMac(mac);
    }

    static OneWayProcessor wrapJceMac(Mac mac) {
        return new JceMacProcessor(mac);
    }

    private static final class JceDigestProcessor implements OneWayProcessor {
        private final MessageDigest messageDigest;

        private JceDigestProcessor(MessageDigest messageDigest) {
            this.messageDigest = messageDigest;
        }

        @Override
        public int getOutputLength() {
            return messageDigest.getDigestLength();
        }

        @Override
        public int writeTo(byte[] output, int offset, int maxLength) {
            Preconditions.checkNotNull(output);
            try {
                return messageDigest.digest(output, offset, maxLength);
            } catch (DigestException e) {
                /* Digest exceptions are not expected for our used digests */
                throw Throwables.propagate(e);
            }
        }

        @Override
        public void reset() {
            messageDigest.reset();
        }

        @Override
        public boolean processBytes(byte[] buf, int off, int len) {
            messageDigest.update(buf, off, len);
            return true;
        }

        @Override
        public byte[] getResult() {
            byte[] output = new byte[getOutputLength()];
            writeTo(output, 0, output.length);
            return output;
        }
    }
    private static final class JceMacProcessor implements OneWayProcessor {
        private final Mac mac;

        private JceMacProcessor(Mac mac) {
            this.mac = mac;
        }

        @Override
        public int getOutputLength() {
            return mac.getMacLength();
        }

        @Override
        public int writeTo(byte[] output, int offset, int maxLength) {
            int macLength = getOutputLength();

            Preconditions.checkNotNull(output);
            Preconditions.checkArgument(maxLength >= macLength);
            Preconditions.checkArgument(maxLength <= (output.length - offset));
            try {
                mac.doFinal(output, offset);
            } catch (ShortBufferException e) {
                throw new IllegalArgumentException(e);
            }
            return macLength;
        }

        @Override
        public void reset() {
            mac.reset();
        }

        @Override
        public boolean processBytes(byte[] buf, int off, int len) {
            mac.update(buf, off, len);
            return true;
        }

        @Override
        public byte[] getResult() {
            byte[] output = new byte[getOutputLength()];
            writeTo(output, 0, output.length);
            return output;
        }
    }
}
