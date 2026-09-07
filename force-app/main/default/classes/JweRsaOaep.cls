/**
 * @description RSAES-OAEP key wrapping: the `RSA-OAEP` and `RSA-OAEP-256` key management
 * algorithms of JWE, which encrypt the content encryption key under the recipient's RSA key.
 * The hash passed to the constructor is what separates the two: SHA-1 for `RSA-OAEP`, SHA-256
 * for `RSA-OAEP-256`. It is used both for the label hash and inside MGF1, as RFC 8017 §B.2.1
 * requires.
 *
 * The RSA primitive runs on `JweBigInt`, that is, on `Decimal` arithmetic, because Apex has no
 * big integer type. This is what makes the operation expensive: an RSA-2048 wrap costs roughly
 * 70-130 ms of CPU and an unwrap 200-260 ms, which is a meaningful share of the synchronous
 * governor limit. One wrap or unwrap per transaction is fine; a loop over many is not.
 *
 * RFC 7518 §4.3 defines no label for RSA-OAEP in JOSE, so the label L of RFC 8017 §7.1 is
 * always the empty string and its hash is computed once per instance.
 *
 * Padding checks cannot be made constant time in Apex, so a decoding failure is
 * distinguishable by timing from a different decoding failure. Every one of them raises the
 * same message, and the caller of `unwrap` is expected to replace the failed key with random
 * bytes and let the failure surface at the authentication tag check, which is what removes the
 * oracle (RFC 7516 §11.5).
 *
 * @see https://www.rfc-editor.org/rfc/rfc8017#section-7.1
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-4.3
 */
public inherited sharing class JweRsaOaep implements JweKeyEncryption {
    /** @description Digest length hLen in octets, by platform hash name. */
    private static final Map<String, Integer> HASH_LENGTHS = new Map<String, Integer>{
        'SHA1' => 20,
        'SHA-256' => 32,
        'SHA-512' => 64
    };

    /**
     * @description The one message every decoding failure raises. Which check failed is never
     * disclosed: that distinction is what a padding oracle is built from.
     */
    private static final String FAILURE = 'RSA-OAEP decryption failed';

    /** @description The 0x01 octet that separates the padding string PS from the message. */
    private static final Integer SEPARATOR = 1;

    private final String hashAlgorithm;
    private final Integer hashLength;
    private final JweBytes labelHash;

    /**
     * @description Creates a wrapper for one hash algorithm.
     * @param hashAlgorithm The platform hash name: 'SHA1' for RSA-OAEP, 'SHA-256' for
     * RSA-OAEP-256, or 'SHA-512'.
     * @throws JweException When the hash algorithm is null or not one of those three.
     */
    public JweRsaOaep(String hashAlgorithm) {
        if (!HASH_LENGTHS.containsKey(hashAlgorithm)) {
            throw new JweException('Unsupported hash algorithm: ' + hashAlgorithm);
        }

        this.hashAlgorithm = hashAlgorithm;
        this.hashLength = HASH_LENGTHS.get(hashAlgorithm);
        this.labelHash = digest(JweBytes.empty());
    }

    /**
     * @description RSAES-OAEP-ENCRYPT: encrypts a content encryption key under a public key.
     * A fresh seed is drawn for every call, so the same key wrapped twice yields two different
     * ciphertexts, which is what OAEP needs to be non-deterministic.
     * @param contentEncryptionKey The key to wrap.
     * @param key The recipient key. Only n and e are used.
     * @return The wrapped key, exactly as long as the modulus.
     * @throws JweException When an argument is null, the modulus is too small for the hash, or
     * the key to wrap is too long for the modulus.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-7.1.1
     */
    public Blob wrap(Blob contentEncryptionKey, JweKey key) {
        if (contentEncryptionKey == null) {
            throw new JweException('The key to wrap cannot be null');
        }

        requireKey(key);

        Integer k = key.modulusOctets();
        JweBytes encoded = encode(
            JweBytes.of(contentEncryptionKey),
            k,
            JweBytes.random(this.hashLength)
        );

        return JweBigInt.fromBytes(encoded.toBlob())
            .modPow(key.publicExponent(), key.modulus())
            .toBlob(k);
    }

    /**
     * @description RSAES-OAEP-DECRYPT: recovers a content encryption key with a private key.
     * Takes the CRT path when the key carries the five CRT members, and verifies its result by
     * re-encrypting under the public exponent: a CRT computation that goes wrong on one of the
     * two factors leaks the factorization of the modulus, so the result is never returned
     * unchecked.
     * @param wrappedKey The ciphertext, which must be exactly as long as the modulus.
     * @param key The recipient key. Requires d, and uses p, q, dp, dq and qi when present.
     * @return The unwrapped content encryption key.
     * @throws JweException With a uniform message when the ciphertext does not decode, and
     * with a specific message when the key cannot decrypt at all.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-7.1.2
     */
    public Blob unwrap(Blob wrappedKey, JweKey key) {
        if (wrappedKey == null) {
            throw new JweException('The wrapped key cannot be null');
        }

        requireKey(key);

        if (!key.hasPrivateExponent()) {
            throw new JweException('Unwrapping requires a key with a private exponent d');
        }

        Integer k = key.modulusOctets();
        requireModulusFitsHash(k);

        // RFC 8017 §7.1.2 step 1.b: a ciphertext of the wrong length, or one that is not a
        // valid representative modulo n, is rejected before any private key operation.
        if (wrappedKey.size() != k) {
            throw new JweException(FAILURE);
        }

        JweBigInt ciphertext = JweBigInt.fromBytes(wrappedKey);

        if (!ciphertext.isLessThan(key.modulus())) {
            throw new JweException(FAILURE);
        }

        return decode(JweBytes.of(recover(ciphertext, key).toBlob(k))).toBlob();
    }

    /**
     * @description Applies the private key to a ciphertext representative, through the CRT
     * path when the key allows it.
     *
     * A CRT result is verified by re-encrypting it under the public exponent. A computation
     * that goes wrong on one of the two factors would otherwise hand out the factorization of
     * the modulus, which is the Bellcore fault attack.
     * @param ciphertext The ciphertext representative.
     * @param key The recipient key.
     * @return The message representative.
     * @throws JweException With the uniform message when the CRT result does not verify.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-5.1.2
     */
    private JweBigInt recover(JweBigInt ciphertext, JweKey key) {
        if (!key.hasCrtParameters()) {
            return ciphertext.modPow(key.privateExponent(), key.modulus());
        }

        JweBigInt message = ciphertext.modPowCrt(key.crtParameters());

        if (!message.modPow(key.publicExponent(), key.modulus()).equals(ciphertext)) {
            throw new JweException(FAILURE);
        }

        return message;
    }

    /**
     * @description EME-OAEP encoding: builds the encoded message EM of exactly k octets from
     * the message M and a seed.
     *
     * EM = 0x00 || maskedSeed || maskedDB, where DB = lHash || PS || 0x01 || M. The seed is a
     * parameter rather than drawn here so that the published RFC 8017 vectors, which fix it,
     * can be reproduced.
     * @param message The message to encode.
     * @param k The length of the encoded message in octets, that is, the modulus length.
     * @param seed hLen random octets.
     * @return The encoded message.
     * @throws JweException When k is too small for the hash or the message is too long.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-7.1.1
     */
    @TestVisible
    private JweBytes encode(JweBytes message, Integer k, JweBytes seed) {
        requireModulusFitsHash(k);

        Integer maximumLength = k - 2 * this.hashLength - 2;

        if (message.size() > maximumLength) {
            throw new JweException(
                'A message of ' +
                    message.size() +
                    ' octets does not fit in ' +
                    maximumLength +
                    ' octets of ' +
                    this.hashAlgorithm +
                    ' OAEP payload'
            );
        }

        JweBytes dataBlock = JweBytes.concat(
            new List<JweBytes>{
                this.labelHash,
                JweBytes.zeros(maximumLength - message.size()),
                JweBytes.ofValues(new List<Integer>{ SEPARATOR }),
                message
            }
        );

        JweBytes maskedDataBlock = dataBlock.xor(mgf1(seed, k - this.hashLength - 1));
        JweBytes maskedSeed = seed.xor(mgf1(maskedDataBlock, this.hashLength));

        return JweBytes.concat(
            new List<JweBytes>{ JweBytes.zeros(1), maskedSeed, maskedDataBlock }
        );
    }

    /**
     * @description EME-OAEP decoding: recovers the message M from an encoded message EM.
     * @param encoded The encoded message, k octets.
     * @return The recovered message.
     * @throws JweException With the uniform message when any check of RFC 8017 §7.1.2 step 3
     * fails.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-7.1.2
     */
    @TestVisible
    private JweBytes decode(JweBytes encoded) {
        Integer k = encoded.size();

        if (k < 2 * this.hashLength + 2 || encoded.at(0) != 0) {
            throw new JweException(FAILURE);
        }

        JweBytes maskedSeed = encoded.slice(1, 1 + this.hashLength);
        JweBytes maskedDataBlock = encoded.slice(1 + this.hashLength, k);

        JweBytes seed = maskedSeed.xor(mgf1(maskedDataBlock, this.hashLength));
        JweBytes dataBlock = maskedDataBlock.xor(mgf1(seed, k - this.hashLength - 1));

        // The label hash is attacker influenced through the ciphertext, so it is compared
        // without an early return, like an authentication tag.
        if (!this.labelHash.equalsConstantTime(dataBlock.slice(0, this.hashLength))) {
            throw new JweException(FAILURE);
        }

        return dataBlock.slice(messageStart(dataBlock), dataBlock.size());
    }

    /**
     * @description Finds where the message begins inside a data block: after the label hash,
     * the padding string PS of zeroed octets, and the 0x01 separator.
     * @param dataBlock The unmasked data block.
     * @return The position of the first octet of the message.
     * @throws JweException With the uniform message when there is no separator, or when the
     * padding before it is not zeroed, either of which means the block was not built by
     * EME-OAEP.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-7.1.2
     */
    private Integer messageStart(JweBytes dataBlock) {
        Integer separator = dataBlock.indexOf(SEPARATOR, this.hashLength);

        if (separator == -1) {
            throw new JweException(FAILURE);
        }

        for (Integer i = this.hashLength; i < separator; i++) {
            if (dataBlock.at(i) != 0) {
                throw new JweException(FAILURE);
            }
        }

        return separator + 1;
    }

    /**
     * @description MGF1: expands a seed into a mask of the requested length by hashing the
     * seed with an incrementing counter.
     * @param seed The seed to expand.
     * @param maskLength The requested mask length in octets.
     * @return The mask.
     * @see https://www.rfc-editor.org/rfc/rfc8017#appendix-B.2.1
     */
    @TestVisible
    private JweBytes mgf1(JweBytes seed, Integer maskLength) {
        List<JweBytes> blocks = new List<JweBytes>();
        Integer produced = 0;

        for (Integer counter = 0; produced < maskLength; counter++) {
            blocks.add(
                digest(JweBytes.concat(new List<JweBytes>{ seed, JweBytes.i2osp4(counter) }))
            );
            produced += this.hashLength;
        }

        return JweBytes.concat(blocks).slice(0, maskLength);
    }

    private JweBytes digest(JweBytes data) {
        return JweBytes.of(Crypto.generateDigest(this.hashAlgorithm, data.toBlob()));
    }

    private void requireModulusFitsHash(Integer k) {
        Integer minimum = 2 * this.hashLength + 2;

        if (k < minimum) {
            throw new JweException(
                'A modulus of ' +
                    k +
                    ' octets is too small for ' +
                    this.hashAlgorithm +
                    ' OAEP, which needs at least ' +
                    minimum
            );
        }
    }

    private static void requireKey(JweKey key) {
        if (key == null) {
            throw new JweException('The key cannot be null');
        }
    }
}
