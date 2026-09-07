/**
 * @description JSON Web Encryption (RFC 7516) in Compact Serialization: encrypts a payload
 * into a five part token and decrypts one back, in native Apex.
 *
 * A token is `header.encryptedKey.iv.ciphertext.tag`, every part base64url without padding.
 * An instance is configured with the algorithms it accepts, and the key travels with each
 * message:
 *
 * ```
 * Jwe jwe = new Jwe(new JweHeader('RSA-OAEP-256', 'A256CBC-HS512').withKeyId('2026-09'));
 * String token = jwe.encrypt('{"sub":"1234"}', JweKey.fromJson(publicJwk));
 * String payload = jwe.decrypt(token, JweKey.fromJson(privateJwk));
 *
 * Jwe shared = new Jwe(new JweHeader('dir', 'A256CBC-HS512'));
 * String direct = shared.encrypt('{"sub":"1234"}', JweKey.fromSecretHex(sharedKeyHex));
 * ```
 *
 * The algorithms are configuration and the key is a parameter, which is the split the two
 * things actually have: a recipient decides in advance what it accepts, and then handles
 * whatever keys and messages arrive. Where those keys are stored is no business of this
 * library.
 *
 * Four decisions in here are security decisions rather than design ones:
 *
 * 1. The configured header decides the algorithms, and a token claiming different ones is
 *    rejected. The token never gets to choose how it will be processed.
 * 2. The content encryption key and the initialization vector are drawn fresh for every
 *    `encrypt`, from the platform CSPRNG.
 * 3. A key that fails to unwrap is replaced by random bytes and the failure surfaces at the
 *    authentication tag, so an attacker cannot tell a bad wrapped key from a bad ciphertext.
 * 4. Everything that depends on a received token fails with one message, `JWE decryption
 *    failed`. Configuration mistakes, which do not depend on attacker input, say what is wrong.
 *
 * Cost: with `dir` an encryption or decryption is a few milliseconds. With RSA-2048 a wrap
 * costs roughly 70-130 ms of CPU and an unwrap 200-260 ms, because Apex has no big integer
 * type and the arithmetic runs on `Decimal`. Budget one token per transaction, not a loop.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7516
 */
public inherited sharing class Jwe {
    /** @description The `alg` value of direct encryption: the recipient already has the key. */
    private static final String DIRECT = 'dir';

    /**
     * @description The one message every failure that depends on a received token carries.
     * @see https://www.rfc-editor.org/rfc/rfc7516#section-11.5
     */
    private static final String FAILURE = 'JWE decryption failed';

    private static final String SEPARATOR = '.';
    private static final Integer PART_COUNT = 5;

    /** @description The hash each supported key management algorithm uses inside OAEP. */
    private static final Map<String, String> KEY_ENCRYPTION_HASHES = new Map<String, String>{
        'RSA-OAEP' => 'SHA1',
        'RSA-OAEP-256' => 'SHA-256'
    };

    private final JweHeader header;
    private final JweAesCbcHmac contentEncryption;
    private final JweKeyEncryption keyEncryption;

    /**
     * @description A fixed initialization vector, for reproducing a published vector in a
     * test. It is consumed by the next `encrypt` and then discarded, so even a test cannot
     * reuse an initialization vector across two messages by accident.
     */
    @TestVisible
    private Blob injectedIv;

    /**
     * @description Configures the algorithms this instance will produce and accept.
     * @param header The protected header. `alg` must be `dir`, `RSA-OAEP` or `RSA-OAEP-256`,
     * and `enc` must be `A128CBC-HS256`, `A192CBC-HS384` or `A256CBC-HS512`.
     * @throws JweException When the header is null or names an algorithm this library does
     * not implement.
     */
    public Jwe(JweHeader header) {
        requireNotNull(header, 'The protected header');

        this.header = header;
        this.contentEncryption = new JweAesCbcHmac(header.enc());
        this.keyEncryption = isDirect() ? null : keyEncryptionFor(header.alg());
    }

    /**
     * @description Encrypts a payload into a compact token.
     * @param payload The text to encrypt.
     * @param key The recipient's key: an RSA key for `RSA-OAEP` and `RSA-OAEP-256`, of which
     * only `n` and `e` are used, or a symmetric key for `dir`.
     * @return The token: five base64url parts separated by dots.
     * @throws JweException When the payload is blank, or the key is missing, of the wrong kind
     * for the configured algorithm, or of the wrong length.
     * @see https://www.rfc-editor.org/rfc/rfc7516#section-5.1
     */
    public String encrypt(String payload, JweKey key) {
        if (String.isBlank(payload)) {
            throw new JweException('The payload cannot be blank');
        }

        requireKey(key);

        String encodedHeader = this.header.encode();
        Blob contentKey = isDirect()
            ? sharedContentKey(key)
            : JweBytes.random(this.contentEncryption.keyOctets()).toBlob();
        String encodedKey = isDirect()
            ? ''
            : JweBase64Url.encode(this.keyEncryption.wrap(contentKey, key));
        Blob iv = nextInitializationVector();

        // The additional authenticated data is the encoded header as octets of ASCII, which is
        // what ties the algorithms the token declares to the ciphertext it carries.
        JweAesCbcHmac.Encrypted encrypted = this.contentEncryption.encrypt(
            contentKey,
            iv,
            Blob.valueOf(encodedHeader),
            Blob.valueOf(payload)
        );

        return String.join(
            new List<String>{
                encodedHeader,
                encodedKey,
                JweBase64Url.encode(iv),
                JweBase64Url.encode(encrypted.ciphertext),
                JweBase64Url.encode(encrypted.tag)
            },
            SEPARATOR
        );
    }

    /**
     * @description Decrypts a compact token.
     * @param token The token to decrypt.
     * @param key The recipient's key: an RSA key carrying `d` for `RSA-OAEP` and
     * `RSA-OAEP-256`, or the symmetric key for `dir`.
     * @return The payload.
     * @throws JweException With the message `JWE decryption failed` for anything wrong with
     * the token, and with a specific message when the key cannot decrypt at all.
     * @see https://www.rfc-editor.org/rfc/rfc7516#section-5.2
     */
    public String decrypt(String token, JweKey key) {
        requireKey(key);

        // Not a property of the token: a key without its private exponent can never decrypt
        // anything, so saying so is not an oracle.
        if (!isDirect() && !key.hasPrivateExponent()) {
            throw new JweException('Decrypting requires a key with a private exponent d');
        }

        if (String.isBlank(token)) {
            throw new JweException(FAILURE);
        }

        // Keep trailing empty parts: a `dir` token ends with an empty encrypted key, and a
        // token with a missing last part must be rejected rather than silently shortened.
        List<String> parts = token.split('\\' + SEPARATOR, -1);

        if (parts.size() != PART_COUNT) {
            throw new JweException(FAILURE);
        }

        Token received = decode(parts);

        if (!this.header.hasSameAlgorithms(received.header)) {
            throw new JweException(FAILURE);
        }

        try {
            return this.contentEncryption.decrypt(
                    contentKeyFor(received, key),
                    received.iv,
                    Blob.valueOf(received.encodedHeader),
                    new JweAesCbcHmac.Encrypted(received.ciphertext, received.tag)
                )
                .toString();
        } catch (Exception e) {
            throw new JweException(FAILURE);
        }
    }

    /**
     * @description The content encryption key of a received token: the shared one, or the one
     * the token carries wrapped.
     * @param received The decoded token.
     * @param key The recipient's key.
     * @return The key to decrypt the ciphertext with.
     * @throws JweException With the uniform message when a direct token carries a wrapped key,
     * which RFC 7518 §4.5 leaves empty.
     */
    private Blob contentKeyFor(Token received, JweKey key) {
        if (!isDirect()) {
            return unwrapOrSubstitute(received.wrappedKey, key);
        }

        if (received.wrappedKey.size() != 0) {
            throw new JweException(FAILURE);
        }

        return sharedContentKey(key);
    }

    /**
     * @description Reads the five parts of a token. Either all of them decode, or the token is
     * rejected: which part was malformed is not something the sender needs to be told.
     * @param parts The five dot separated parts.
     * @return The decoded parts.
     * @throws JweException With the uniform message when any part is not what it claims to be.
     */
    private Token decode(List<String> parts) {
        try {
            Token received = new Token();
            received.encodedHeader = parts[0];
            received.header = JweHeader.parse(parts[0]);
            received.wrappedKey = JweBase64Url.decode(parts[1]);
            received.iv = JweBase64Url.decode(parts[2]);
            received.ciphertext = JweBase64Url.decode(parts[3]);
            received.tag = JweBase64Url.decode(parts[4]);

            return received;
        } catch (Exception e) {
            throw new JweException(FAILURE);
        }
    }

    /**
     * @description Unwraps the content encryption key, or invents one.
     *
     * A wrapped key that does not unwrap, or unwraps to the wrong length, is replaced by
     * random bytes of the right length. The decryption then fails at the authentication tag,
     * exactly as a tampered ciphertext would. Reporting the unwrap failure instead would
     * answer, one ciphertext at a time, whether a chosen value is a valid RSA-OAEP encoding,
     * which is the oracle Bleichenbacher-style attacks are built on.
     * @param wrappedKey The encrypted key from the token.
     * @param key The recipient's key.
     * @return The unwrapped key, or a random key of the same length.
     * @see https://www.rfc-editor.org/rfc/rfc7516#section-11.5
     */
    private Blob unwrapOrSubstitute(Blob wrappedKey, JweKey key) {
        Blob contentKey;

        try {
            contentKey = this.keyEncryption.unwrap(wrappedKey, key);
        } catch (Exception e) {
            contentKey = null;
        }

        if (contentKey == null || contentKey.size() != this.contentEncryption.keyOctets()) {
            return JweBytes.random(this.contentEncryption.keyOctets()).toBlob();
        }

        return contentKey;
    }

    private Blob sharedContentKey(JweKey key) {
        Blob secret = key.secret();

        if (secret.size() != this.contentEncryption.keyOctets()) {
            throw new JweException(
                this.header.enc() +
                    ' needs a shared key of ' +
                    this.contentEncryption.keyOctets() +
                    ' octets, and this one has ' +
                    secret.size()
            );
        }

        return secret;
    }

    private void requireKey(JweKey key) {
        requireNotNull(key, 'The key');

        if (isDirect() && !key.isSymmetric()) {
            throw new JweException(
                'Direct encryption needs a symmetric key: a JWK with kty oct, or one built with JweKey.fromSecretHex'
            );
        }

        if (!isDirect() && key.isSymmetric()) {
            throw new JweException(
                this.header.alg() + ' needs an RSA key, and this one is symmetric'
            );
        }
    }

    private Blob nextInitializationVector() {
        if (this.injectedIv == null) {
            return JweBytes.random(this.contentEncryption.ivOctets()).toBlob();
        }

        Blob iv = this.injectedIv;
        this.injectedIv = null;

        return iv;
    }

    private Boolean isDirect() {
        // Not `==`: Apex string equality ignores case, and RFC 7515 §4.1.1 does not.
        return DIRECT.equals(this.header.alg());
    }

    private static JweKeyEncryption keyEncryptionFor(String alg) {
        if (!KEY_ENCRYPTION_HASHES.containsKey(alg)) {
            throw new JweException('Unsupported key management algorithm: ' + alg);
        }

        return new JweRsaOaep(KEY_ENCRYPTION_HASHES.get(alg));
    }

    private static void requireNotNull(Object value, String description) {
        if (value == null) {
            throw new JweException(description + ' cannot be null');
        }
    }

    /** @description The five parts of a received token, decoded. */
    private class Token {
        private String encodedHeader;
        private JweHeader header;
        private Blob wrappedKey;
        private Blob iv;
        private Blob ciphertext;
        private Blob tag;
    }
}
