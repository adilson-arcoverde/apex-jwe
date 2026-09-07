/**
 * @description RSAES-OAEP behavior. The encoding is pinned by the published RFC 8017 vectors,
 * which fix the seed and therefore the whole encoded message; the wrapping is pinned by round
 * trips, and end to end by the external tokens in JweTest.
 */
@IsTest(isParallel=true)
private class JweRsaOaepTest {
    // Classic EME-OAEP vector (RSAES-OAEP / PKCS#1 v2.1): fixed message and seed, k = 128.
    private static final String MESSAGE_HEX = 'd436e99569fd32a7c8a05bbc90d32c49';
    private static final String SHA1_SEED_HEX = 'aafd12f659cae63489b479e5076ddec2f06cb58f';
    private static final String SHA1_ENCODED_HEX = '00eb7a19ace9e3006350e329504b45e2ca82310b26dcd87d5c68f1eea8f55267c31b2e8bb4251f84d7e0b2c04626f5aff93edcfb25c9c2b3ff8ae10e839a2ddb4cdcfe4ff47728b4a1b7c1362baad29ab48d2869d5024121435811591be392f982fb3e87d095aeb40448db972f3ac14f7bc275195281ce32d2f1b76d4d353e2d';
    private static final String SHA256_SEED_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    private static final String SHA256_ENCODED_HEX = '004eee339ef41d3a7a7d104069e63a463daf098666e08c0f0363ce7f396942ea4e9344c47fca4af717407eda5bbc04e0a2927ac9d4fc20ea3f18c681d71e31c2d104a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12c51c7bf7768390f8d842ac9cb62349779a7537a7833a962b33bdac61fe50f71878a10779e7f';
    private static final String MGF1_SEED_HEX = '0102030405';
    private static final String MGF1_MASK_HEX = 'bd6bb5ad281e38ed94f0488f7878f7389e404370164e54daf4e395150d1bbad5d424';

    // SHA-1 of the empty octet string: the label hash of every JOSE RSA-OAEP operation, since
    // RFC 7518 §4.3 defines no label.
    private static final String SHA1_EMPTY_HASH_HEX = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
    private static final Integer SHA1_LENGTH = 20;
    private static final Integer VECTOR_MODULUS_OCTETS = 128;

    // A 512 bit content encryption key, the size A256CBC-HS512 uses.
    private static final String CEK_HEX =
        '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f' +
        '303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f';

    @IsTest
    static void encodesTheSha1ReferenceVector() {
        JweBytes encoded = new JweRsaOaep('SHA1')
            .encode(
                JweBytes.ofHex(MESSAGE_HEX),
                VECTOR_MODULUS_OCTETS,
                JweBytes.ofHex(SHA1_SEED_HEX)
            );

        Assert.areEqual(
            SHA1_ENCODED_HEX,
            encoded.toHex(),
            'RFC 8017 EME-OAEP vector with SHA-1 and a fixed seed'
        );
    }

    @IsTest
    static void encodesTheSha256ReferenceVector() {
        JweBytes encoded = new JweRsaOaep('SHA-256')
            .encode(
                JweBytes.ofHex(MESSAGE_HEX),
                VECTOR_MODULUS_OCTETS,
                JweBytes.ofHex(SHA256_SEED_HEX)
            );

        Assert.areEqual(
            SHA256_ENCODED_HEX,
            encoded.toHex(),
            'EME-OAEP vector with SHA-256 and a fixed seed'
        );
    }

    @IsTest
    static void decodesTheReferenceVectors() {
        Assert.areEqual(
            MESSAGE_HEX,
            new JweRsaOaep('SHA1').decode(JweBytes.ofHex(SHA1_ENCODED_HEX)).toHex(),
            'Decoding the SHA-1 vector recovers the message'
        );
        Assert.areEqual(
            MESSAGE_HEX,
            new JweRsaOaep('SHA-256').decode(JweBytes.ofHex(SHA256_ENCODED_HEX)).toHex(),
            'Decoding the SHA-256 vector recovers the message'
        );
    }

    @IsTest
    static void generatesTheMgf1ReferenceMask() {
        JweBytes mask = new JweRsaOaep('SHA1').mgf1(JweBytes.ofHex(MGF1_SEED_HEX), 34);

        Assert.areEqual(
            MGF1_MASK_HEX,
            mask.toHex(),
            'MGF1 vector: 34 octets span two SHA-1 blocks and truncate the second'
        );
        Assert.areEqual(
            0,
            new JweRsaOaep('SHA1').mgf1(JweBytes.ofHex(MGF1_SEED_HEX), 0).size(),
            'A mask of zero octets needs no block'
        );
    }

    @IsTest
    static void usesTheEmptyLabelHash() {
        JweBytes encoded = new JweRsaOaep('SHA1')
            .encode(
                JweBytes.ofHex(MESSAGE_HEX),
                VECTOR_MODULUS_OCTETS,
                JweBytes.ofHex(SHA1_SEED_HEX)
            );

        JweBytes dataBlock = unmask(new JweRsaOaep('SHA1'), encoded);

        Assert.areEqual(
            SHA1_EMPTY_HASH_HEX,
            dataBlock.slice(0, SHA1_LENGTH).toHex(),
            'The data block opens with the hash of the empty label'
        );
    }

    @IsTest
    static void wrapsAndUnwrapsWithTheCrtPath() {
        Blob cek = EncodingUtil.convertFromHex(CEK_HEX);
        JweRsaOaep oaep = new JweRsaOaep('SHA-256');
        JweKey key = JweTestKeys.rsaPrivateKey();

        Blob wrapped = oaep.wrap(cek, key);

        Assert.areEqual(
            256,
            wrapped.size(),
            'The ciphertext is exactly as long as the modulus (RFC 8017 I2OSP)'
        );
        Assert.areEqual(
            CEK_HEX,
            EncodingUtil.convertToHex(oaep.unwrap(wrapped, key)),
            'The CRT path recovers the key that was wrapped'
        );
    }

    @IsTest
    static void unwrapsWithoutTheCrtMembers() {
        Blob cek = EncodingUtil.convertFromHex(CEK_HEX);
        JweRsaOaep oaep = new JweRsaOaep('SHA-256');

        Blob wrapped = oaep.wrap(cek, JweTestKeys.rsaPublicKey());

        Assert.areEqual(
            CEK_HEX,
            EncodingUtil.convertToHex(oaep.unwrap(wrapped, JweTestKeys.rsaPrivateKeyWithoutCrt())),
            'The private exponent alone recovers the same key'
        );
    }

    @IsTest
    static void drawsAFreshSeedForEveryWrap() {
        Blob cek = EncodingUtil.convertFromHex(CEK_HEX);
        JweRsaOaep oaep = new JweRsaOaep('SHA-256');
        JweKey key = JweTestKeys.rsaPublicKey();

        Assert.areNotEqual(
            EncodingUtil.convertToHex(oaep.wrap(cek, key)),
            EncodingUtil.convertToHex(oaep.wrap(cek, key)),
            'The same key wrapped twice must yield two different ciphertexts'
        );
    }

    @IsTest
    static void wrapsWithSha1ForTheRsaOaepAlgorithm() {
        Blob cek = EncodingUtil.convertFromHex(CEK_HEX);
        JweRsaOaep oaep = new JweRsaOaep('SHA1');
        JweKey key = JweTestKeys.rsaPrivateKey();

        Assert.areEqual(
            CEK_HEX,
            EncodingUtil.convertToHex(oaep.unwrap(oaep.wrap(cek, key), key)),
            'RSA-OAEP with SHA-1 round trips like RSA-OAEP-256'
        );
    }

    @IsTest
    static void rejectsUnsupportedHashAlgorithms() {
        for (String hash : new List<String>{ null, 'MD5', 'sha-256', 'SHA-384' }) {
            try {
                new JweRsaOaep(hash);
                Assert.fail('Unsupported hash algorithm must be rejected: ' + hash);
            } catch (JweException e) {
                Assert.areEqual(
                    'Unsupported hash algorithm: ' + hash,
                    e.getMessage(),
                    'Failure names the algorithm'
                );
            }
        }
    }

    @IsTest
    static void rejectsMissingArguments() {
        JweRsaOaep oaep = new JweRsaOaep('SHA-256');
        JweKey key = JweTestKeys.rsaPublicKey();
        Blob cek = EncodingUtil.convertFromHex(CEK_HEX);

        try {
            oaep.wrap(null, key);
            Assert.fail('A null key to wrap must be rejected');
        } catch (JweException e) {
            Assert.areEqual('The key to wrap cannot be null', e.getMessage(), 'Null payload');
        }

        try {
            oaep.wrap(cek, null);
            Assert.fail('A null recipient key must be rejected');
        } catch (JweException e) {
            Assert.areEqual('The key cannot be null', e.getMessage(), 'Null key on wrap');
        }

        try {
            oaep.unwrap(null, key);
            Assert.fail('A null ciphertext must be rejected');
        } catch (JweException e) {
            Assert.areEqual('The wrapped key cannot be null', e.getMessage(), 'Null ciphertext');
        }

        try {
            oaep.unwrap(cek, null);
            Assert.fail('A null recipient key must be rejected');
        } catch (JweException e) {
            Assert.areEqual('The key cannot be null', e.getMessage(), 'Null key on unwrap');
        }
    }

    @IsTest
    static void refusesToUnwrapWithAPublicKey() {
        try {
            new JweRsaOaep('SHA-256')
                .unwrap(EncodingUtil.convertFromHex('00'.repeat(256)), JweTestKeys.rsaPublicKey());
            Assert.fail('A key without d cannot unwrap');
        } catch (JweException e) {
            Assert.areEqual(
                'Unwrapping requires a key with a private exponent d',
                e.getMessage(),
                'Configuration failures stay specific: this one does not depend on the token'
            );
        }
    }

    @IsTest
    static void rejectsCiphertextOutsideTheValidRange() {
        JweRsaOaep oaep = new JweRsaOaep('SHA-256');
        JweKey key = JweTestKeys.rsaPrivateKey();

        // Wrong length, and the right length but not a representative modulo n. Both are
        // rejected before the private key is touched, and both report the uniform failure.
        for (
            Blob ciphertext : new List<Blob>{
                EncodingUtil.convertFromHex('00'.repeat(255)),
                EncodingUtil.convertFromHex('ff'.repeat(256))
            }
        ) {
            try {
                oaep.unwrap(ciphertext, key);
                Assert.fail('Invalid ciphertext must be rejected');
            } catch (JweException e) {
                Assert.areEqual(
                    'RSA-OAEP decryption failed',
                    e.getMessage(),
                    'Every token dependent failure carries the same message'
                );
            }
        }
    }

    @IsTest
    static void rejectsACrtResultThatDoesNotVerify() {
        // A key whose CRT members disagree with n is, to this class, indistinguishable from a
        // CRT computation that went wrong on one of the two factors. Returning such a result
        // hands out the factorization of the modulus, so it is verified and discarded instead
        // (Boneh, DeMillo and Lipton, 1997).
        Map<String, Object> members = (Map<String, Object>) JSON.deserializeUntyped(
            JweTestKeys.RSA_PRIVATE_JWK
        );
        members.put('qi', members.get('dq'));

        JweRsaOaep oaep = new JweRsaOaep('SHA-256');
        Blob wrapped = oaep.wrap(EncodingUtil.convertFromHex(CEK_HEX), JweTestKeys.rsaPublicKey());

        try {
            oaep.unwrap(wrapped, JweKey.fromJson(JSON.serialize(members)));
            Assert.fail('A CRT result that does not verify must not be returned');
        } catch (JweException e) {
            Assert.areEqual(
                'RSA-OAEP decryption failed',
                e.getMessage(),
                'A failed fault check reports the uniform failure like any other'
            );
        }
    }

    @IsTest
    static void rejectsEncodedMessagesThatWereNotBuiltByOaep() {
        JweRsaOaep oaep = new JweRsaOaep('SHA1');
        JweBytes labelHash = JweBytes.ofHex(SHA1_EMPTY_HASH_HEX);
        JweBytes seed = JweBytes.ofHex(SHA1_SEED_HEX);
        Integer dataBlockLength = VECTOR_MODULUS_OCTETS - SHA1_LENGTH - 1;

        Map<String, JweBytes> cases = new Map<String, JweBytes>();

        // Below the minimum length of RFC 8017 §7.1.2 step 1.c: 2 * hLen + 2 octets.
        cases.put('too short', JweBytes.zeros(2 * SHA1_LENGTH + 1));

        // A leading octet that is not 0x00, so the encoded message is not a representative.
        cases.put(
            'leading octet set',
            JweBytes.concat(
                new List<JweBytes>{
                    JweBytes.ofValues(new List<Integer>{ 1 }),
                    JweBytes.ofHex(SHA1_ENCODED_HEX).slice(1, VECTOR_MODULUS_OCTETS)
                }
            )
        );

        // The label hash does not match, which is what a tampered ciphertext produces.
        cases.put(
            'label hash mismatch',
            mask(
                oaep,
                JweBytes.concat(
                    new List<JweBytes>{
                        JweBytes.zeros(SHA1_LENGTH),
                        JweBytes.zeros(dataBlockLength - SHA1_LENGTH - 1),
                        JweBytes.ofValues(new List<Integer>{ 1 })
                    }
                ),
                seed
            )
        );

        // No 0x01 separator at all: nothing marks where the message starts.
        cases.put(
            'no separator',
            mask(
                oaep,
                JweBytes.concat(
                    new List<JweBytes>{ labelHash, JweBytes.zeros(dataBlockLength - SHA1_LENGTH) }
                ),
                seed
            )
        );

        // A non-zero octet inside the padding string PS.
        cases.put(
            'padding not zeroed',
            mask(
                oaep,
                JweBytes.concat(
                    new List<JweBytes>{
                        labelHash,
                        JweBytes.ofValues(new List<Integer>{ 0, 7 }),
                        JweBytes.ofValues(new List<Integer>{ 1 }),
                        JweBytes.zeros(dataBlockLength - SHA1_LENGTH - 3)
                    }
                ),
                seed
            )
        );

        for (String description : cases.keySet()) {
            try {
                oaep.decode(cases.get(description));
                Assert.fail('Must be rejected: ' + description);
            } catch (JweException e) {
                Assert.areEqual(
                    'RSA-OAEP decryption failed',
                    e.getMessage(),
                    'Which check failed must not be disclosed: ' + description
                );
            }
        }
    }

    @IsTest
    static void rejectsMessagesThatDoNotFitTheModulus() {
        JweRsaOaep oaep = new JweRsaOaep('SHA-256');

        try {
            // k - 2 * hLen - 2 = 62 octets fit under SHA-256 with a 128 octet modulus.
            oaep.encode(JweBytes.zeros(63), VECTOR_MODULUS_OCTETS, JweBytes.zeros(32));
            Assert.fail('A message one octet too long must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'A message of 63 octets does not fit in 62 octets of SHA-256 OAEP payload',
                e.getMessage(),
                'Failure states both lengths'
            );
        }
    }

    @IsTest
    static void rejectsModuliTooSmallForTheHash() {
        try {
            new JweRsaOaep('SHA-512').encode(JweBytes.empty(), 129, JweBytes.zeros(64));
            Assert.fail('SHA-512 OAEP needs at least 130 octets of modulus');
        } catch (JweException e) {
            Assert.areEqual(
                'A modulus of 129 octets is too small for SHA-512 OAEP, which needs at least 130',
                e.getMessage(),
                'Failure states the minimum'
            );
        }
    }

    /**
     * @description Builds an encoded message from an arbitrary data block, using the masking
     * of the class under test. It is how a data block that OAEP itself would never produce is
     * fed to the decoder.
     * @param oaep The instance under test, for its MGF1.
     * @param dataBlock The data block to mask, k - hLen - 1 octets.
     * @param seed The seed to mask it with.
     * @return The encoded message.
     */
    private static JweBytes mask(JweRsaOaep oaep, JweBytes dataBlock, JweBytes seed) {
        JweBytes maskedDataBlock = dataBlock.xor(oaep.mgf1(seed, dataBlock.size()));
        JweBytes maskedSeed = seed.xor(oaep.mgf1(maskedDataBlock, SHA1_LENGTH));

        return JweBytes.concat(
            new List<JweBytes>{ JweBytes.zeros(1), maskedSeed, maskedDataBlock }
        );
    }

    /**
     * @description Reverses the masking of an encoded message, to inspect the data block.
     * @param oaep The instance under test, for its MGF1.
     * @param encoded The encoded message.
     * @return The unmasked data block.
     */
    private static JweBytes unmask(JweRsaOaep oaep, JweBytes encoded) {
        JweBytes maskedSeed = encoded.slice(1, 1 + SHA1_LENGTH);
        JweBytes maskedDataBlock = encoded.slice(1 + SHA1_LENGTH, encoded.size());
        JweBytes seed = maskedSeed.xor(oaep.mgf1(maskedDataBlock, SHA1_LENGTH));

        return maskedDataBlock.xor(oaep.mgf1(seed, maskedDataBlock.size()));
    }
}
