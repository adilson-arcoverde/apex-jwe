/**
 * @description Content encryption behavior, pinned by the RFC 7518 Appendix B vectors. These
 * vectors fix the key, the plaintext, the initialization vector and the additional
 * authenticated data, and therefore the ciphertext and the tag: they are what proves the
 * composition is assembled in the right order, with the right key halves and the right AL.
 *
 * Extracting this algorithm out of the token assembly is what made them testable at all.
 */
@IsTest(isParallel=true)
private class JweAesCbcHmacTest {
    private static final String A128 = 'A128CBC-HS256';
    private static final String A192 = 'A192CBC-HS384';
    private static final String A256 = 'A256CBC-HS512';

    // Shared by every case of RFC 7518 Appendix B.
    private static final String PLAINTEXT_HEX =
        '41206369706865722073797374656d206d757374206e6f7420626520726571' +
        '756972656420746f206265207365637265742c20616e64206974206d757374' +
        '2062652061626c6520746f2066616c6c20696e746f207468652068616e6473' +
        '206f662074686520656e656d7920776974686f757420696e636f6e76656e69' +
        '656e6365';
    private static final String IV_HEX = '1af38c2dc2b96ffdd86694092341bc04';
    private static final String AAD_HEX =
        '546865207365636f6e64207072696e6369706c65206f6620417567757374' + '65204b6572636b686f666673';
    // AL: the 42 octets of AAD are 336 bits, 0x150.
    private static final String AL_HEX = '0000000000000150';

    // B.1, A128CBC-HS256.
    private static final String B1_KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    private static final String B1_CIPHERTEXT_HEX =
        'c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9' +
        'a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c7032336' +
        '09d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b' +
        '384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade5' +
        '4b8851ffb598f7f80074b9473c82e2db';
    private static final String B1_TAG_HEX = '652c3fa36b0a7c5b3219fab3a30bc1c4';

    // B.2, A192CBC-HS384.
    private static final String B2_KEY_HEX =
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
        '202122232425262728292a2b2c2d2e2f';
    private static final String B2_CIPHERTEXT_HEX =
        'ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb' +
        '000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b226d174621' +
        '4bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c21' +
        '05bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927' +
        'f280adc91ac0c4e79c7b11efc60054e3';
    private static final String B2_TAG_HEX = '8490ac0e58949bfe51875d733f93ac2075168039ccc733d7';

    // B.3, A256CBC-HS512.
    private static final String B3_KEY_HEX =
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
    private static final String B3_CIPHERTEXT_HEX =
        '4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd' +
        '822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b' +
        '36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3' +
        'a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950b' +
        'be2638d09dd7a4930930806d0703b1f6';
    private static final String B3_TAG_HEX = '4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5';

    @IsTest
    static void encryptsTheAppendixB1Vector() {
        JweAesCbcHmac.Encrypted result = new JweAesCbcHmac(A128)
            .encrypt(blobOf(B1_KEY_HEX), blobOf(IV_HEX), blobOf(AAD_HEX), blobOf(PLAINTEXT_HEX));

        Assert.areEqual(
            B1_CIPHERTEXT_HEX,
            hexOf(result.ciphertext),
            'RFC 7518 Appendix B.1 ciphertext, including the block of PKCS#7 padding that a 128 octet plaintext adds'
        );
        Assert.areEqual(
            B1_TAG_HEX,
            hexOf(result.tag),
            'RFC 7518 Appendix B.1 tag: HMAC-SHA-256 truncated to 16 octets'
        );
    }

    @IsTest
    static void encryptsTheAppendixB3Vector() {
        JweAesCbcHmac.Encrypted result = new JweAesCbcHmac(A256)
            .encrypt(blobOf(B3_KEY_HEX), blobOf(IV_HEX), blobOf(AAD_HEX), blobOf(PLAINTEXT_HEX));

        Assert.areEqual(
            B3_CIPHERTEXT_HEX,
            hexOf(result.ciphertext),
            'RFC 7518 Appendix B.3 ciphertext'
        );
        Assert.areEqual(
            B3_TAG_HEX,
            hexOf(result.tag),
            'RFC 7518 Appendix B.3 tag: HMAC-SHA-512 truncated to 32 octets'
        );
    }

    @IsTest
    static void encryptsTheAppendixB2Vector() {
        JweAesCbcHmac.Encrypted result = new JweAesCbcHmac(A192)
            .encrypt(blobOf(B2_KEY_HEX), blobOf(IV_HEX), blobOf(AAD_HEX), blobOf(PLAINTEXT_HEX));

        Assert.areEqual(
            B2_CIPHERTEXT_HEX,
            hexOf(result.ciphertext),
            'RFC 7518 Appendix B.2 ciphertext'
        );
        Assert.areEqual(
            B2_TAG_HEX,
            hexOf(result.tag),
            'RFC 7518 Appendix B.2 tag: HMAC-SHA-384 truncated to 24 octets'
        );
    }

    @IsTest
    static void decryptsTheAppendixVectors() {
        Assert.areEqual(
            PLAINTEXT_HEX,
            hexOf(
                new JweAesCbcHmac(A128)
                    .decrypt(
                        blobOf(B1_KEY_HEX),
                        blobOf(IV_HEX),
                        blobOf(AAD_HEX),
                        new JweAesCbcHmac.Encrypted(blobOf(B1_CIPHERTEXT_HEX), blobOf(B1_TAG_HEX))
                    )
            ),
            'Appendix B.1 decrypts to the published plaintext'
        );
        Assert.areEqual(
            PLAINTEXT_HEX,
            hexOf(
                new JweAesCbcHmac(A256)
                    .decrypt(
                        blobOf(B3_KEY_HEX),
                        blobOf(IV_HEX),
                        blobOf(AAD_HEX),
                        new JweAesCbcHmac.Encrypted(blobOf(B3_CIPHERTEXT_HEX), blobOf(B3_TAG_HEX))
                    )
            ),
            'Appendix B.3 decrypts to the published plaintext'
        );
        Assert.areEqual(
            PLAINTEXT_HEX,
            hexOf(
                new JweAesCbcHmac(A192)
                    .decrypt(
                        blobOf(B2_KEY_HEX),
                        blobOf(IV_HEX),
                        blobOf(AAD_HEX),
                        new JweAesCbcHmac.Encrypted(blobOf(B2_CIPHERTEXT_HEX), blobOf(B2_TAG_HEX))
                    )
            ),
            'Appendix B.2 decrypts to the same plaintext as the other two cases'
        );
    }

    @IsTest
    static void authenticatesTheDataLengthField() {
        // Recomputes the tag independently, to state the MAC input in the test itself:
        // AAD || IV || ciphertext || AL, keyed with the first half of the CEK, truncated to
        // half the digest. AL is what stops the boundary between AAD and ciphertext from moving.
        Blob macKey = blobOf(B1_KEY_HEX.left(32));
        Blob macInput = blobOf(AAD_HEX + IV_HEX + B1_CIPHERTEXT_HEX + AL_HEX);
        String digest = hexOf(Crypto.generateMac('hmacSHA256', macInput, macKey));

        Assert.areEqual(
            B1_TAG_HEX,
            digest.left(digest.length() / 2),
            'The tag is the first half of the HMAC over AAD || IV || ciphertext || AL'
        );
    }

    @IsTest
    static void roundTripsWithAFreshInitializationVector() {
        JweAesCbcHmac aead = new JweAesCbcHmac(A256);
        Blob cek = JweBytes.random(aead.keyOctets()).toBlob();
        Blob iv = JweBytes.random(aead.ivOctets()).toBlob();
        Blob aad = Blob.valueOf('eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0');
        Blob plaintext = Blob.valueOf('{"sub":"round trip"}');

        JweAesCbcHmac.Encrypted result = aead.encrypt(cek, iv, aad, plaintext);

        Assert.areEqual(
            '{"sub":"round trip"}',
            aead.decrypt(cek, iv, aad, result).toString(),
            'What this algorithm encrypts, it decrypts'
        );
    }

    @IsTest
    static void rejectsTamperedInput() {
        JweAesCbcHmac aead = new JweAesCbcHmac(A128);
        Blob cek = blobOf(B1_KEY_HEX);
        Blob iv = blobOf(IV_HEX);
        Blob aad = blobOf(AAD_HEX);

        Map<String, JweAesCbcHmac.Encrypted> tampered = new Map<String, JweAesCbcHmac.Encrypted>{
            'tag' => new JweAesCbcHmac.Encrypted(
                blobOf(B1_CIPHERTEXT_HEX),
                blobOf('652c3fa36b0a7c5b3219fab3a30bc1c5')
            ),
            'truncated tag' => new JweAesCbcHmac.Encrypted(
                blobOf(B1_CIPHERTEXT_HEX),
                blobOf(B1_TAG_HEX.left(30))
            ),
            'ciphertext' => new JweAesCbcHmac.Encrypted(
                blobOf('d8' + B1_CIPHERTEXT_HEX.substring(2)),
                blobOf(B1_TAG_HEX)
            )
        };

        for (String part : tampered.keySet()) {
            try {
                aead.decrypt(cek, iv, aad, tampered.get(part));
                Assert.fail('A tampered ' + part + ' must be rejected');
            } catch (JweException e) {
                Assert.areEqual(
                    'Content decryption failed',
                    e.getMessage(),
                    'Which part was tampered with must not be disclosed: ' + part
                );
            }
        }
    }

    @IsTest
    static void rejectsATamperedInitializationVectorAndAdditionalData() {
        JweAesCbcHmac aead = new JweAesCbcHmac(A128);
        JweAesCbcHmac.Encrypted authentic = new JweAesCbcHmac.Encrypted(
            blobOf(B1_CIPHERTEXT_HEX),
            blobOf(B1_TAG_HEX)
        );

        try {
            aead.decrypt(
                blobOf(B1_KEY_HEX),
                blobOf('1bf38c2dc2b96ffdd86694092341bc04'),
                blobOf(AAD_HEX),
                authentic
            );
            Assert.fail('The initialization vector is authenticated, so a change must be caught');
        } catch (JweException e) {
            Assert.areEqual('Content decryption failed', e.getMessage(), 'Tampered IV');
        }

        try {
            aead.decrypt(
                blobOf(B1_KEY_HEX),
                blobOf(IV_HEX),
                blobOf(AAD_HEX.substring(2)),
                authentic
            );
            Assert.fail('The additional data is authenticated, so a change must be caught');
        } catch (JweException e) {
            Assert.areEqual('Content decryption failed', e.getMessage(), 'Tampered AAD');
        }
    }

    @IsTest
    static void failsUniformlyWhenAnAuthenticatedCiphertextIsNotAValidCbcSequence() {
        // A ciphertext that is not a whole number of AES blocks, carrying the tag it deserves.
        // It gets past the tag check and fails inside AES, and must still be indistinguishable
        // from any other failure.
        Blob shortCiphertext = blobOf('00112233445566');
        Blob macInput = blobOf(AAD_HEX + IV_HEX + '00112233445566' + AL_HEX);
        String digest = hexOf(
            Crypto.generateMac('hmacSHA256', macInput, blobOf(B1_KEY_HEX.left(32)))
        );

        try {
            new JweAesCbcHmac(A128)
                .decrypt(
                    blobOf(B1_KEY_HEX),
                    blobOf(IV_HEX),
                    blobOf(AAD_HEX),
                    new JweAesCbcHmac.Encrypted(
                        shortCiphertext,
                        blobOf(digest.left(digest.length() / 2))
                    )
                );
            Assert.fail('A ciphertext that is not a valid CBC sequence must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Content decryption failed',
                e.getMessage(),
                'A failure inside AES reports like a failed tag'
            );
        }
    }

    @IsTest
    static void reportsTheSizesItNeeds() {
        JweAesCbcHmac a128 = new JweAesCbcHmac(A128);
        JweAesCbcHmac a256 = new JweAesCbcHmac(A256);

        Assert.areEqual(32, a128.keyOctets(), 'A128CBC-HS256 splits a 256 bit CEK into two halves');
        Assert.areEqual(
            48,
            new JweAesCbcHmac(A192).keyOctets(),
            'A192CBC-HS384 splits a 384 bit CEK into two halves'
        );
        Assert.areEqual(64, a256.keyOctets(), 'A256CBC-HS512 splits a 512 bit CEK into two halves');
        Assert.areEqual(16, a128.ivOctets(), 'The IV is one AES block');
        Assert.areEqual(16, a256.ivOctets(), 'The IV is one AES block regardless of key size');
    }

    @IsTest
    static void rejectsUnsupportedAlgorithms() {
        // The GCM family is what Apex genuinely cannot do: Crypto offers AES in CBC mode only.
        for (String enc : new List<String>{ null, 'A128GCM', 'A256GCM', 'a128cbc-hs256' }) {
            try {
                new JweAesCbcHmac(enc);
                Assert.fail('Unsupported content encryption must be rejected: ' + enc);
            } catch (JweException e) {
                Assert.areEqual(
                    'Unsupported content encryption algorithm: ' + enc,
                    e.getMessage(),
                    'Failure names the algorithm, and the comparison is case sensitive'
                );
            }
        }
    }

    @IsTest
    static void rejectsKeysOfTheWrongLength() {
        try {
            new JweAesCbcHmac(A256)
                .encrypt(
                    blobOf(B1_KEY_HEX),
                    blobOf(IV_HEX),
                    blobOf(AAD_HEX),
                    blobOf(PLAINTEXT_HEX)
                );
            Assert.fail('A 32 octet key cannot drive AES-256 with HMAC-SHA-512');
        } catch (JweException e) {
            Assert.areEqual(
                'A256CBC-HS512 needs a content encryption key of 64 octets, and this one has 32',
                e.getMessage(),
                'Failure states both lengths'
            );
        }

        try {
            new JweAesCbcHmac(A128)
                .decrypt(
                    blobOf(B3_KEY_HEX),
                    blobOf(IV_HEX),
                    blobOf(AAD_HEX),
                    new JweAesCbcHmac.Encrypted(blobOf(B1_CIPHERTEXT_HEX), blobOf(B1_TAG_HEX))
                );
            Assert.fail('A 64 octet key is not what A128CBC-HS256 consumes');
        } catch (JweException e) {
            Assert.areEqual(
                'A128CBC-HS256 needs a content encryption key of 32 octets, and this one has 64',
                e.getMessage(),
                'The key length is a caller error on both sides'
            );
        }
    }

    @IsTest
    static void rejectsAnInitializationVectorOfTheWrongLength() {
        JweAesCbcHmac aead = new JweAesCbcHmac(A128);

        try {
            aead.encrypt(
                blobOf(B1_KEY_HEX),
                blobOf('1af38c2d'),
                blobOf(AAD_HEX),
                blobOf(PLAINTEXT_HEX)
            );
            Assert.fail('An IV that is not one AES block must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'The initialization vector must be 16 octets, and this one is 4',
                e.getMessage(),
                'On encryption the IV is the caller of this library, so the failure is specific'
            );
        }

        try {
            aead.decrypt(
                blobOf(B1_KEY_HEX),
                blobOf('1af38c2d'),
                blobOf(AAD_HEX),
                new JweAesCbcHmac.Encrypted(blobOf(B1_CIPHERTEXT_HEX), blobOf(B1_TAG_HEX))
            );
            Assert.fail('An IV that is not one AES block must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Content decryption failed',
                e.getMessage(),
                'On decryption the IV comes from the token, so the failure is uniform'
            );
        }
    }

    @IsTest
    static void rejectsMissingArgumentsOnEncryption() {
        JweAesCbcHmac aead = new JweAesCbcHmac(A128);
        Blob cek = blobOf(B1_KEY_HEX);
        Blob iv = blobOf(IV_HEX);
        Blob aad = blobOf(AAD_HEX);
        Blob plaintext = blobOf(PLAINTEXT_HEX);

        Map<String, String> expected = new Map<String, String>{
            'key' => 'The content encryption key cannot be null',
            'aad' => 'The additional authenticated data cannot be null',
            'plaintext' => 'The plaintext cannot be null',
            'iv' => 'The initialization vector cannot be null'
        };

        try {
            aead.encrypt(null, iv, aad, plaintext);
            Assert.fail('A null key must be rejected');
        } catch (JweException e) {
            Assert.areEqual(expected.get('key'), e.getMessage(), 'Null key on encryption');
        }

        try {
            aead.encrypt(cek, iv, null, plaintext);
            Assert.fail('A null AAD must be rejected');
        } catch (JweException e) {
            Assert.areEqual(expected.get('aad'), e.getMessage(), 'Null AAD');
        }

        try {
            aead.encrypt(cek, iv, aad, null);
            Assert.fail('A null plaintext must be rejected');
        } catch (JweException e) {
            Assert.areEqual(expected.get('plaintext'), e.getMessage(), 'Null plaintext');
        }

        try {
            aead.encrypt(cek, null, aad, plaintext);
            Assert.fail('A null IV must be rejected');
        } catch (JweException e) {
            Assert.areEqual(expected.get('iv'), e.getMessage(), 'Null IV');
        }
    }

    @IsTest
    static void rejectsMissingArgumentsOnDecryption() {
        JweAesCbcHmac aead = new JweAesCbcHmac(A128);
        Blob cek = blobOf(B1_KEY_HEX);
        Blob iv = blobOf(IV_HEX);
        Blob aad = blobOf(AAD_HEX);
        JweAesCbcHmac.Encrypted authentic = new JweAesCbcHmac.Encrypted(
            blobOf(B1_CIPHERTEXT_HEX),
            blobOf(B1_TAG_HEX)
        );

        try {
            aead.decrypt(cek, iv, aad, null);
            Assert.fail('A null ciphertext and tag pair must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'The ciphertext and tag pair cannot be null',
                e.getMessage(),
                'Null pair'
            );
        }

        try {
            aead.decrypt(cek, iv, aad, new JweAesCbcHmac.Encrypted(null, blobOf(B1_TAG_HEX)));
            Assert.fail('A null ciphertext must be rejected');
        } catch (JweException e) {
            Assert.areEqual('The ciphertext cannot be null', e.getMessage(), 'Null ciphertext');
        }

        try {
            aead.decrypt(
                cek,
                iv,
                aad,
                new JweAesCbcHmac.Encrypted(blobOf(B1_CIPHERTEXT_HEX), null)
            );
            Assert.fail('A null tag must be rejected');
        } catch (JweException e) {
            Assert.areEqual('The authentication tag cannot be null', e.getMessage(), 'Null tag');
        }

        try {
            aead.decrypt(cek, iv, null, authentic);
            Assert.fail('A null AAD must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'The additional authenticated data cannot be null',
                e.getMessage(),
                'Null AAD on decryption'
            );
        }

        try {
            aead.decrypt(cek, null, aad, authentic);
            Assert.fail('A null IV must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'The initialization vector cannot be null',
                e.getMessage(),
                'Null IV on decryption'
            );
        }
    }

    private static Blob blobOf(String hex) {
        return EncodingUtil.convertFromHex(hex);
    }

    private static String hexOf(Blob data) {
        return EncodingUtil.convertToHex(data);
    }
}
