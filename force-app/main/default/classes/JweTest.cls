/**
 * @description Behavior of the facade: the five part assembly, the algorithm pinning, the
 * freshness of the per-message material, and the single failure message that everything about
 * a received token collapses into.
 *
 * The assertions that carry the weight are the six tokens produced outside Apex, by two
 * independent producers, which must keep decrypting to their published payloads. Until the
 * implementation being replaced was removed, tokens also had to cross with it in both
 * directions; those tests are in the history of this file.
 */
@IsTest(isParallel=true)
private class JweTest {
    private static final String DIR = 'dir';
    private static final String RSA_OAEP = 'RSA-OAEP';
    private static final String RSA_OAEP_256 = 'RSA-OAEP-256';
    private static final String A128 = 'A128CBC-HS256';
    private static final String A256 = 'A256CBC-HS512';
    private static final String FAILURE = 'JWE decryption failed';
    private static final String PAYLOAD = '{"sub":"1234567890","name":"A Payload"}';

    private static Jwe jweFor(String alg, String enc) {
        return new Jwe(new JweHeader(alg, enc));
    }

    /**
     * @description The pre-shared key of the interop tokens, as a symmetric JWK. The first 32
     * of its 64 octets are the A128CBC-HS256 key.
     * @param enc The content encryption algorithm the key is for.
     * @return The key.
     */
    private static JweKey sharedKey(String enc) {
        return JweKey.fromSecretHex(
            enc == A128 ? JweTestTokens.AES_SHARED_KEY.left(64) : JweTestTokens.AES_SHARED_KEY
        );
    }

    @IsTest
    static void decryptsADirectTokenFromAnExternalLibrary() {
        Assert.areEqual(
            JweTestTokens.DIR_A128CBC_HS256_PAYLOAD,
            jweFor(DIR, A128).decrypt(JweTestTokens.DIR_A128CBC_HS256_TOKEN, sharedKey(A128)),
            'A dir token produced by jose must decrypt unchanged'
        );
    }

    @IsTest
    static void decryptsRsaOaepTokensFromAnExternalLibrary() {
        Assert.areEqual(
            JweTestTokens.RSA_OAEP_A128CBC_HS256_PAYLOAD,
            jweFor(RSA_OAEP, A128)
                .decrypt(JweTestTokens.RSA_OAEP_A128CBC_HS256_TOKEN, JweTestKeys.rsaPrivateKey()),
            'RSA-OAEP with SHA-1 and A128CBC-HS256'
        );
        Assert.areEqual(
            JweTestTokens.RSA_OAEP_256_A128CBC_HS256_PAYLOAD,
            jweFor(RSA_OAEP_256, A128)
                .decrypt(
                    JweTestTokens.RSA_OAEP_256_A128CBC_HS256_TOKEN,
                    JweTestKeys.rsaPrivateKey()
                ),
            'RSA-OAEP-256 with A128CBC-HS256'
        );
    }

    @IsTest
    static void decryptsAnRsaOaep256TokenFromAnExternalLibrary() {
        Assert.areEqual(
            JweTestTokens.RSA_OAEP_256_A256CBC_HS512_PAYLOAD,
            jweFor(RSA_OAEP_256, A256)
                .decrypt(
                    JweTestTokens.RSA_OAEP_256_A256CBC_HS512_TOKEN,
                    JweTestKeys.rsaPrivateKey()
                ),
            'RSA-OAEP-256 with A256CBC-HS512'
        );
    }

    @IsTest
    static void decryptsTokensFromASecondExternalProducer() {
        // Produced with the Node `crypto` module instead of jose. Two independent producers of
        // the same wire format is a stronger statement than one.
        Assert.areEqual(
            JweTestTokens.DIR_A256CBC_HS512_PAYLOAD,
            jweFor(DIR, A256).decrypt(JweTestTokens.DIR_A256CBC_HS512_TOKEN, sharedKey(A256)),
            'dir with A256CBC-HS512, and a payload ending in characters the two base64 alphabets disagree on'
        );
        Assert.areEqual(
            JweTestTokens.RSA_OAEP_A256CBC_HS512_PAYLOAD,
            jweFor(RSA_OAEP, A256)
                .decrypt(JweTestTokens.RSA_OAEP_A256CBC_HS512_TOKEN, JweTestKeys.rsaPrivateKey()),
            'RSA-OAEP with SHA-1 and A256CBC-HS512'
        );
    }

    @IsTest
    static void decryptsATokenAddressedToAKeyGivenAsAnOctJwk() {
        // The same shared key, expressed the way RFC 7518 §6.4 expresses a symmetric key,
        // instead of as hex.
        String octJwk =
            '{"kty":"oct","k":"' +
            JweBase64Url.encode(
                EncodingUtil.convertFromHex(JweTestTokens.AES_SHARED_KEY.left(64))
            ) +
            '"}';

        Assert.areEqual(
            JweTestTokens.DIR_A128CBC_HS256_PAYLOAD,
            jweFor(DIR, A128)
                .decrypt(JweTestTokens.DIR_A128CBC_HS256_TOKEN, JweKey.fromJson(octJwk)),
            'A symmetric key reads the same from a JWK as from hex'
        );
    }

    @IsTest
    static void roundTripsDirectEncryption() {
        // Local names cannot echo the constants: Apex identifiers are case insensitive, so a
        // variable called a256 would shadow the constant A256.
        Jwe wide = jweFor(DIR, A256);
        Jwe narrow = jweFor(DIR, A128);

        Assert.areEqual(
            PAYLOAD,
            wide.decrypt(wide.encrypt(PAYLOAD, sharedKey(A256)), sharedKey(A256)),
            'dir with A256CBC-HS512'
        );
        Assert.areEqual(
            PAYLOAD,
            narrow.decrypt(narrow.encrypt(PAYLOAD, sharedKey(A128)), sharedKey(A128)),
            'dir with A128CBC-HS256'
        );
    }

    @IsTest
    static void roundTripsKeyWrapping() {
        Jwe jwe = jweFor(RSA_OAEP_256, A256);
        JweKey key = JweTestKeys.rsaPrivateKey();

        Assert.areEqual(
            PAYLOAD,
            jwe.decrypt(jwe.encrypt(PAYLOAD, key), key),
            'RSA-OAEP-256 with A256CBC-HS512'
        );
    }

    @IsTest
    static void roundTripsKeyWrappingWithSha1() {
        Jwe jwe = jweFor(RSA_OAEP, A128);
        JweKey key = JweTestKeys.rsaPrivateKey();

        Assert.areEqual(
            PAYLOAD,
            jwe.decrypt(jwe.encrypt(PAYLOAD, key), key),
            'RSA-OAEP with A128CBC-HS256'
        );
    }

    @IsTest
    static void encryptsForARecipientHoldingOnlyThePublicKey() {
        Jwe jwe = jweFor(RSA_OAEP_256, A256);

        String token = jwe.encrypt(PAYLOAD, JweTestKeys.rsaPublicKey());

        Assert.areEqual(
            PAYLOAD,
            jwe.decrypt(token, JweTestKeys.rsaPrivateKey()),
            'A public key is enough to encrypt, and the private half reads it back'
        );
    }

    @IsTest
    static void servesOneRecipientAfterAnotherOnTheSameInstance() {
        // The key being a parameter is what makes this possible: one configured instance, two
        // recipients, without rebuilding anything.
        Jwe jwe = jweFor(RSA_OAEP_256, A128);

        String forFullKey = jwe.encrypt(PAYLOAD, JweTestKeys.rsaPrivateKey());
        String forPublicHalf = jwe.encrypt(PAYLOAD, JweTestKeys.rsaPublicKey());

        Assert.areEqual(
            PAYLOAD,
            jwe.decrypt(forFullKey, JweTestKeys.rsaPrivateKey()),
            'The first message'
        );
        Assert.areEqual(
            PAYLOAD,
            jwe.decrypt(forPublicHalf, JweTestKeys.rsaPrivateKeyWithoutCrt()),
            'The second message, read with the same key without its CRT members'
        );
    }

    @IsTest
    static void assemblesFivePartsOfStrictBase64Url() {
        String token = jweFor(RSA_OAEP_256, A256).encrypt(PAYLOAD, JweTestKeys.rsaPublicKey());
        List<String> parts = token.split('\\.', -1);

        Assert.areEqual(5, parts.size(), 'A compact token has five parts');
        Assert.isFalse(token.contains('='), 'Base64URL in JOSE carries no padding');
        Assert.isFalse(token.contains('+'), 'The standard alphabet has no place in a token');
        Assert.isFalse(token.contains('/'), 'The standard alphabet has no place in a token');
        Assert.areEqual(
            256,
            JweBase64Url.decode(parts[1]).size(),
            'The wrapped key is exactly as long as the 2048 bit modulus'
        );
        Assert.areEqual(16, JweBase64Url.decode(parts[2]).size(), 'The IV is one AES block');
        Assert.areEqual(
            32,
            JweBase64Url.decode(parts[4]).size(),
            'The A256CBC-HS512 tag is 32 octets'
        );

        JweHeader header = JweHeader.parse(parts[0]);

        Assert.areEqual(RSA_OAEP_256, header.alg(), 'The header declares the key management');
        Assert.areEqual(A256, header.enc(), 'The header declares the content encryption');
    }

    @IsTest
    static void leavesTheEncryptedKeyEmptyInDirectMode() {
        String token = jweFor(DIR, A256).encrypt(PAYLOAD, sharedKey(A256));

        Assert.areEqual(
            '',
            token.split('\\.', -1)[1],
            'With dir there is no key to carry (RFC 7518 §4.5)'
        );
    }

    @IsTest
    static void carriesTheKeyIdentifierWhenGiven() {
        String token = new Jwe(new JweHeader(DIR, A256).withKeyId('2026-09'))
            .encrypt(PAYLOAD, sharedKey(A256));

        Assert.areEqual(
            '2026-09',
            JweHeader.parse(token.split('\\.', -1)[0]).keyId(),
            'A recipient with several keys is told which one was used'
        );
    }

    @IsTest
    static void pinsTheConfiguredAlgorithmsAgainstTheToken() {
        String token = JweTestTokens.DIR_A128CBC_HS256_TOKEN;

        // Configured for a different content encryption than the token declares.
        Assert.areEqual(
            FAILURE,
            failureOf(jweFor(DIR, A256), token, sharedKey(A256), 'a token declaring another enc'),
            'Every failure that depends on the token reports the same way'
        );

        // Configured for key wrapping, offered a dir token.
        Assert.areEqual(
            FAILURE,
            failureOf(
                jweFor(RSA_OAEP_256, A128),
                token,
                JweTestKeys.rsaPrivateKey(),
                'a token declaring another alg'
            ),
            'Every failure that depends on the token reports the same way'
        );

        // The header of the same token, with enc in lower case. RFC 7515 §4.1.1 makes header
        // values case sensitive, and Apex string equality is not, so this is worth pinning.
        List<String> parts = token.split('\\.', -1);
        parts[0] = JweBase64Url.encode(
            Blob.valueOf('{"alg":"dir","enc":"a128cbc-hs256","kid":"interop-5"}')
        );

        Assert.areEqual(
            FAILURE,
            failureOf(
                jweFor(DIR, A128),
                String.join(parts, '.'),
                sharedKey(A128),
                'a token whose enc differs only in case'
            ),
            'Every failure that depends on the token reports the same way'
        );
    }

    @IsTest
    static void failsUniformlyOnMalformedTokens() {
        Jwe jwe = jweFor(DIR, A128);
        String token = JweTestTokens.DIR_A128CBC_HS256_TOKEN;
        List<String> parts = token.split('\\.', -1);

        Map<String, String> cases = new Map<String, String>{
            'null' => null,
            'blank' => '   ',
            'no dots' => 'not-a-token',
            'four parts' => String.join(
                new List<String>{ parts[0], parts[1], parts[2], parts[3] },
                '.'
            ),
            'six parts' => token +
            '.' +
            parts[4],
            'missing tag' => token.substringBeforeLast('.') + '.',
            'header not base64url' => 'not base64url!' + token.substring(token.indexOf('.')),
            'header not json' => JweBase64Url.encode(Blob.valueOf('nonsense')) +
            token.substring(token.indexOf('.'))
        };

        for (String description : cases.keySet()) {
            Assert.areEqual(
                FAILURE,
                failureOf(jwe, cases.get(description), sharedKey(A128), description),
                'Uniform failure for: ' + description
            );
        }
    }

    @IsTest
    static void failsUniformlyOnTamperedParts() {
        Jwe jwe = jweFor(DIR, A128);
        List<String> parts = JweTestTokens.DIR_A128CBC_HS256_TOKEN.split('\\.', -1);

        // Every part is authenticated, so changing any of them must be caught, and caught the
        // same way: an attacker learns nothing about which part was rejected.
        Map<String, Integer> partNames = new Map<String, Integer>{
            'initialization vector' => 2,
            'ciphertext' => 3,
            'tag' => 4
        };

        for (String description : partNames.keySet()) {
            List<String> tampered = parts.clone();
            tampered[partNames.get(description)] = flipFirstCharacter(
                parts[partNames.get(description)]
            );

            Assert.areEqual(
                FAILURE,
                failureOf(
                    jwe,
                    String.join(tampered, '.'),
                    sharedKey(A128),
                    'tampered ' + description
                ),
                'Uniform failure for a tampered ' + description
            );
        }

        // With dir there is nothing to wrap, so a token carrying a key is not a dir token.
        List<String> withKey = parts.clone();
        withKey[1] = 'AQAB';

        Assert.areEqual(
            FAILURE,
            failureOf(
                jwe,
                String.join(withKey, '.'),
                sharedKey(A128),
                'a dir token carrying a wrapped key'
            ),
            'A dir token carrying a wrapped key is not a dir token'
        );
    }

    @IsTest
    static void failsUniformlyWithTheWrongSharedKey() {
        // A key of the right length that is simply not the key. It has to fail exactly like a
        // tampered ciphertext: the tag is what catches both.
        Assert.areEqual(
            FAILURE,
            failureOf(
                jweFor(DIR, A128),
                JweTestTokens.DIR_A128CBC_HS256_TOKEN,
                JweKey.fromSecretHex(JweTestTokens.WRONG_SHARED_KEY),
                'a valid token under the wrong shared key'
            ),
            'Every failure that depends on the token reports the same way'
        );
    }

    @IsTest
    static void failsUniformlyWhenTheWrappedKeyDoesNotUnwrap() {
        // The wrapped key is replaced by random bytes that no private key will decode. The
        // failure has to arrive at the tag check, indistinguishable from a tampered
        // ciphertext, so that a chosen ciphertext learns nothing (RFC 7516 §11.5).
        List<String> parts = JweTestTokens.RSA_OAEP_256_A128CBC_HS256_TOKEN.split('\\.', -1);
        parts[1] = JweBase64Url.encode(JweBytes.random(256).toBlob());

        Assert.areEqual(
            FAILURE,
            failureOf(
                jweFor(RSA_OAEP_256, A128),
                String.join(parts, '.'),
                JweTestKeys.rsaPrivateKey(),
                'a wrapped key that does not unwrap'
            ),
            'Every failure that depends on the token reports the same way'
        );
    }

    @IsTest
    static void drawsFreshMaterialForEveryMessage() {
        Jwe jwe = jweFor(DIR, A256);

        List<String> first = jwe.encrypt(PAYLOAD, sharedKey(A256)).split('\\.', -1);
        List<String> second = jwe.encrypt(PAYLOAD, sharedKey(A256)).split('\\.', -1);

        Assert.areNotEqual(
            first[2],
            second[2],
            'A repeated initialization vector under the same key breaks CBC'
        );
        Assert.areNotEqual(
            first[3],
            second[3],
            'The same payload must not encrypt to the same ciphertext twice'
        );

        Jwe wrapping = jweFor(RSA_OAEP_256, A128);
        JweKey key = JweTestKeys.rsaPublicKey();

        Assert.areNotEqual(
            wrapping.encrypt(PAYLOAD, key).split('\\.', -1)[1],
            wrapping.encrypt(PAYLOAD, key).split('\\.', -1)[1],
            'A fresh content encryption key is wrapped for every message'
        );
    }

    @IsTest
    static void consumesAnInjectedInitializationVectorOnce() {
        Jwe jwe = jweFor(DIR, A256);
        String injected = '1af38c2dc2b96ffdd86694092341bc04';
        jwe.injectedIv = EncodingUtil.convertFromHex(injected);

        String withInjected = jwe.encrypt(PAYLOAD, sharedKey(A256)).split('\\.', -1)[2];
        String afterwards = jwe.encrypt(PAYLOAD, sharedKey(A256)).split('\\.', -1)[2];

        Assert.areEqual(
            injected,
            EncodingUtil.convertToHex(JweBase64Url.decode(withInjected)),
            'The injected vector is used once'
        );
        Assert.areNotEqual(
            withInjected,
            afterwards,
            'And discarded afterwards, so a test cannot reuse it by accident'
        );
    }

    @IsTest
    static void encryptsManyMessagesInOneTransaction() {
        // Direct encryption is cheap enough to run in bulk, and this is where a leak of
        // per-message state, or a governor limit hidden in the primitives, would show up.
        Jwe jwe = jweFor(DIR, A256);
        JweKey key = sharedKey(A256);
        Set<String> tokens = new Set<String>();

        for (Integer i = 0; i < 50; i++) {
            String payload = '{"index":' + i + '}';
            String token = jwe.encrypt(payload, key);
            tokens.add(token);

            Assert.areEqual(payload, jwe.decrypt(token, key), 'Message ' + i + ' must round trip');
        }

        Assert.areEqual(50, tokens.size(), 'Fifty messages must produce fifty distinct tokens');
    }

    @IsTest
    static void refusesToDecryptWithoutThePrivateExponent() {
        try {
            jweFor(RSA_OAEP_256, A256)
                .decrypt(
                    JweTestTokens.RSA_OAEP_256_A256CBC_HS512_TOKEN,
                    JweTestKeys.rsaPublicKey()
                );
            Assert.fail('A public key cannot decrypt');
        } catch (JweException e) {
            Assert.areEqual(
                'Decrypting requires a key with a private exponent d',
                e.getMessage(),
                'This does not depend on the token, so it is not hidden behind the uniform failure'
            );
        }
    }

    @IsTest
    static void rejectsABlankPayload() {
        for (String payload : new List<String>{ null, '', '   ' }) {
            try {
                jweFor(DIR, A256).encrypt(payload, sharedKey(A256));
                Assert.fail('A blank payload is not something to encrypt');
            } catch (JweException e) {
                Assert.areEqual(
                    'The payload cannot be blank',
                    e.getMessage(),
                    'Failure names the cause'
                );
            }
        }
    }

    @IsTest
    static void rejectsAKeyOfTheWrongKindForTheAlgorithm() {
        try {
            jweFor(DIR, A256).encrypt(PAYLOAD, JweTestKeys.rsaPrivateKey());
            Assert.fail('Direct encryption has no use for an RSA key');
        } catch (JweException e) {
            Assert.areEqual(
                'Direct encryption needs a symmetric key: a JWK with kty oct, or one built with JweKey.fromSecretHex',
                e.getMessage(),
                'The failure points at what to build instead'
            );
        }

        try {
            jweFor(RSA_OAEP_256, A256).encrypt(PAYLOAD, sharedKey(A256));
            Assert.fail('Key wrapping needs a key to wrap with');
        } catch (JweException e) {
            Assert.areEqual(
                'RSA-OAEP-256 needs an RSA key, and this one is symmetric',
                e.getMessage(),
                'The failure names the configured algorithm'
            );
        }
    }

    @IsTest
    static void rejectsSharedKeysThatDoNotFitTheAlgorithm() {
        try {
            jweFor(DIR, A256).encrypt(PAYLOAD, sharedKey(A128));
            Assert.fail('A 32 octet shared key is not enough for A256CBC-HS512');
        } catch (JweException e) {
            Assert.areEqual(
                'A256CBC-HS512 needs a shared key of 64 octets, and this one has 32',
                e.getMessage(),
                'Failure states both lengths'
            );
        }

        try {
            JweKey.fromSecretHex('not hex');
            Assert.fail('A shared key that is not hex must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Hex source must have an even number of digits',
                e.getMessage(),
                'The hex reader reports the cause'
            );
        }
    }

    @IsTest
    static void rejectsUnsupportedAlgorithms() {
        for (String alg : new List<String>{ 'RSA1_5', 'ECDH-ES', 'A256KW', 'DIR' }) {
            try {
                jweFor(alg, A256);
                Assert.fail('Unsupported key management must be rejected: ' + alg);
            } catch (JweException e) {
                Assert.areEqual(
                    'Unsupported key management algorithm: ' + alg,
                    e.getMessage(),
                    'Failure names the algorithm, and the comparison is case sensitive'
                );
            }
        }

        try {
            jweFor(RSA_OAEP_256, 'A256GCM');
            Assert.fail('Unsupported content encryption must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Unsupported content encryption algorithm: A256GCM',
                e.getMessage(),
                'The content encryption reports its own vocabulary'
            );
        }
    }

    @IsTest
    static void rejectsMissingConfiguration() {
        try {
            new Jwe(null);
            Assert.fail('A header is required');
        } catch (JweException e) {
            Assert.areEqual('The protected header cannot be null', e.getMessage(), 'Null header');
        }

        try {
            jweFor(RSA_OAEP_256, A256).encrypt(PAYLOAD, null);
            Assert.fail('A key is required to encrypt');
        } catch (JweException e) {
            Assert.areEqual('The key cannot be null', e.getMessage(), 'Null key on encryption');
        }

        try {
            jweFor(RSA_OAEP_256, A256)
                .decrypt(JweTestTokens.RSA_OAEP_256_A256CBC_HS512_TOKEN, null);
            Assert.fail('A key is required to decrypt');
        } catch (JweException e) {
            Assert.areEqual('The key cannot be null', e.getMessage(), 'Null key on decryption');
        }
    }

    /**
     * @description Decrypts a token that must be rejected, and returns the message it was
     * rejected with, so that the assertion stays where the reader looks for it.
     * @param jwe The configured instance.
     * @param token The token to reject.
     * @param key The key to offer it with.
     * @param description What is wrong with it, for the failure message.
     * @return The message of the raised exception.
     */
    @SuppressWarnings('PMD.ExcessiveParameterList')
    private static String failureOf(Jwe jwe, String token, JweKey key, String description) {
        try {
            jwe.decrypt(token, key);
            Assert.fail('Must be rejected: ' + description);
        } catch (JweException e) {
            return e.getMessage();
        }

        return null;
    }

    private static String flipFirstCharacter(String part) {
        String first = part.left(1) == 'A' ? 'B' : 'A';

        return first + part.substring(1);
    }
}
