/**
 * @description AES-CBC with HMAC-SHA-2, the content encryption family of JWE:
 * `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`. It is an AEAD built by composition:
 * the plaintext is
 * encrypted with AES in CBC mode, and the ciphertext, the initialization vector and the
 * additional authenticated data are then authenticated with HMAC.
 *
 * The content encryption key carries both keys at once. Its first half is the MAC key and its
 * second half the encryption key, so a 512 bit CEK drives AES-256 with HMAC-SHA-512. The
 * authentication tag is the HMAC output truncated to half its length, which is why the digest
 * is twice the size of the tag it produces.
 *
 * The authenticated data length AL, the last field of the MAC input, is the bit length of the
 * additional authenticated data as a 64 bit big-endian integer. Without it, an attacker could
 * move the boundary between the additional data and the ciphertext.
 *
 * All three cases of RFC 7518 Appendix B are reproduced octet for octet by the test suite,
 * which is the whole point of having this algorithm as a type of its own.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-5.2
 */
public inherited sharing class JweAesCbcHmac {
    /** @description The supported content encryption algorithms, by their JWE `enc` value. */
    private static final Map<String, Profile> PROFILES = new Map<String, Profile>{
        'A128CBC-HS256' => new Profile('AES128', 'hmacSHA256', 32),
        'A192CBC-HS384' => new Profile('AES192', 'hmacSHA384', 48),
        'A256CBC-HS512' => new Profile('AES256', 'hmacSHA512', 64)
    };

    /** @description AES block size, and therefore the length of every CBC initialization vector. */
    private static final Integer IV_OCTETS = 16;

    /** @description AL is a 64 bit field, and Apex I2OSP covers 32 bits at a time. */
    private static final Integer AL_HIGH_OCTETS = 4;

    /**
     * @description The one message every failure that depends on received data raises. A
     * distinction between "the tag did not match" and "the padding was wrong" is the
     * difference an attacker needs.
     */
    private static final String FAILURE = 'Content decryption failed';

    private final String enc;
    private final Profile profile;

    /**
     * @description Creates a content encryption for one algorithm.
     * @param enc The JWE `enc` value: 'A128CBC-HS256', 'A192CBC-HS384' or 'A256CBC-HS512'.
     * @throws JweException When the algorithm is null or not supported.
     */
    public JweAesCbcHmac(String enc) {
        if (!PROFILES.containsKey(enc)) {
            throw new JweException('Unsupported content encryption algorithm: ' + enc);
        }

        this.enc = enc;
        this.profile = PROFILES.get(enc);
    }

    /**
     * @description The length of the content encryption key this algorithm consumes, counting
     * both halves. It is what a caller generating a fresh CEK has to ask for.
     * @return The CEK length in octets.
     */
    public Integer keyOctets() {
        return this.profile.keyOctets;
    }

    /**
     * @description The length of the initialization vector, which is the AES block size.
     * @return The IV length in octets.
     */
    public Integer ivOctets() {
        return IV_OCTETS;
    }

    /**
     * @description Encrypts and authenticates a plaintext.
     * @param contentEncryptionKey The CEK, MAC key followed by encryption key.
     * @param iv The initialization vector, 16 octets, fresh for every message.
     * @param additionalData The data to authenticate without encrypting. In a JWE token it is
     * the ASCII of the encoded protected header.
     * @param plaintext The data to encrypt.
     * @return The ciphertext and its authentication tag.
     * @throws JweException When an argument is null or of the wrong length.
     * @see https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.1
     */
    // Four arguments because RFC 7518 §5.2 defines the operation over exactly these four
    // inputs; bundling them would hide what the algorithm takes.
    @SuppressWarnings('PMD.ExcessiveParameterList')
    public Encrypted encrypt(
        Blob contentEncryptionKey,
        Blob iv,
        Blob additionalData,
        Blob plaintext
    ) {
        requireKey(contentEncryptionKey);
        requireNotNull(additionalData, 'The additional authenticated data');
        requireNotNull(plaintext, 'The plaintext');
        requireNotNull(iv, 'The initialization vector');

        if (iv.size() != IV_OCTETS) {
            throw new JweException(
                'The initialization vector must be ' +
                    IV_OCTETS +
                    ' octets, and this one is ' +
                    iv.size()
            );
        }

        JweBytes cek = JweBytes.of(contentEncryptionKey);

        // Not wrapped in a try: the checks above cover everything Crypto.encrypt rejects for
        // this cipher, and what remains is a governor limit, which Apex does not let a library
        // catch anyway.
        Blob ciphertext = Crypto.encrypt(this.profile.cipher, encryptionKey(cek), iv, plaintext);

        return new Encrypted(ciphertext, tag(macKey(cek), iv, additionalData, ciphertext));
    }

    /**
     * @description Verifies the authentication tag and decrypts.
     *
     * The tag is checked first and the ciphertext is only decrypted if it matches, as RFC 7518
     * §5.2.2.2 requires: decrypting first and reporting a padding error would answer questions
     * about the plaintext that the tag exists to refuse.
     * @param contentEncryptionKey The CEK, MAC key followed by encryption key.
     * @param iv The initialization vector from the token.
     * @param additionalData The data that was authenticated without being encrypted.
     * @param encrypted The ciphertext and the tag received.
     * @return The plaintext.
     * @throws JweException With a uniform message when the tag does not match or the
     * ciphertext does not decrypt, and with a specific message when an argument is null or the
     * key is of the wrong length.
     * @see https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.2
     */
    // Four arguments because RFC 7518 §5.2 defines the operation over exactly these four
    // inputs; bundling them would hide what the algorithm takes.
    @SuppressWarnings('PMD.ExcessiveParameterList')
    public Blob decrypt(
        Blob contentEncryptionKey,
        Blob iv,
        Blob additionalData,
        Encrypted encrypted
    ) {
        requireKey(contentEncryptionKey);
        requireNotNull(additionalData, 'The additional authenticated data');
        requireNotNull(encrypted, 'The ciphertext and tag pair');
        requireNotNull(encrypted.ciphertext, 'The ciphertext');
        requireNotNull(encrypted.tag, 'The authentication tag');
        requireNotNull(iv, 'The initialization vector');

        // Unlike on the encryption side, the length of the initialization vector here comes
        // from the token, so it is reported as a decryption failure and not as a caller error.
        if (iv.size() != IV_OCTETS) {
            throw new JweException(FAILURE);
        }

        JweBytes cek = JweBytes.of(contentEncryptionKey);
        JweBytes expected = JweBytes.of(tag(macKey(cek), iv, additionalData, encrypted.ciphertext));

        if (!expected.equalsConstantTime(JweBytes.of(encrypted.tag))) {
            throw new JweException(FAILURE);
        }

        try {
            return Crypto.decrypt(
                this.profile.cipher,
                encryptionKey(cek),
                iv,
                encrypted.ciphertext
            );
        } catch (Exception e) {
            // Unreachable through a token produced by this library: the tag above already
            // authenticated this ciphertext. It stays because a tag can only prove that the
            // octets are the ones that were sent, not that they are a valid CBC sequence.
            throw new JweException(FAILURE);
        }
    }

    /**
     * @description Computes the authentication tag over AAD || IV || ciphertext || AL, then
     * truncates it to half the digest length.
     * @param macKey The first half of the CEK.
     * @param iv The initialization vector.
     * @param additionalData The additional authenticated data.
     * @param ciphertext The ciphertext.
     * @return The tag.
     * @see https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.1
     */
    // Four arguments because RFC 7518 §5.2 defines the operation over exactly these four
    // inputs; bundling them would hide what the algorithm takes.
    @SuppressWarnings('PMD.ExcessiveParameterList')
    private Blob tag(Blob macKey, Blob iv, Blob additionalData, Blob ciphertext) {
        JweBytes macInput = JweBytes.concat(
            new List<JweBytes>{
                JweBytes.of(additionalData),
                JweBytes.of(iv),
                JweBytes.of(ciphertext),
                authenticatedDataLength(additionalData)
            }
        );

        JweBytes digest = JweBytes.of(
            Crypto.generateMac(this.profile.mac, macInput.toBlob(), macKey)
        );

        return digest.slice(0, digest.size() / 2).toBlob();
    }

    /**
     * @description AL: the bit length of the additional authenticated data, as a 64 bit
     * big-endian integer.
     * @param additionalData The additional authenticated data.
     * @return The eight octets of AL.
     */
    private static JweBytes authenticatedDataLength(Blob additionalData) {
        return JweBytes.concat(
            new List<JweBytes>{
                JweBytes.zeros(AL_HIGH_OCTETS),
                JweBytes.i2osp4(additionalData.size() * 8)
            }
        );
    }

    private Blob macKey(JweBytes cek) {
        return cek.slice(0, cek.size() / 2).toBlob();
    }

    private Blob encryptionKey(JweBytes cek) {
        return cek.slice(cek.size() / 2, cek.size()).toBlob();
    }

    private void requireKey(Blob contentEncryptionKey) {
        requireNotNull(contentEncryptionKey, 'The content encryption key');

        if (contentEncryptionKey.size() != this.profile.keyOctets) {
            throw new JweException(
                this.enc +
                    ' needs a content encryption key of ' +
                    this.profile.keyOctets +
                    ' octets, and this one has ' +
                    contentEncryptionKey.size()
            );
        }
    }

    private static void requireNotNull(Object value, String description) {
        if (value == null) {
            throw new JweException(description + ' cannot be null');
        }
    }

    /**
     * @description The two outputs of an authenticated encryption, which travel together as
     * two parts of a JWE token.
     */
    public class Encrypted {
        /** @description The encrypted plaintext. */
        public final Blob ciphertext;

        /** @description The tag that authenticates the ciphertext, the IV and the AAD. */
        public final Blob tag;

        /**
         * @description Pairs a ciphertext with its tag, to be verified and decrypted.
         * @param ciphertext The ciphertext.
         * @param tag The authentication tag.
         */
        public Encrypted(Blob ciphertext, Blob tag) {
            this.ciphertext = ciphertext;
            this.tag = tag;
        }
    }

    /** @description What a JWE `enc` value means in terms of platform primitives. */
    private class Profile {
        private final String cipher;
        private final String mac;
        private final Integer keyOctets;

        private Profile(String cipher, String mac, Integer keyOctets) {
            this.cipher = cipher;
            this.mac = mac;
            this.keyOctets = keyOctets;
        }
    }
}
