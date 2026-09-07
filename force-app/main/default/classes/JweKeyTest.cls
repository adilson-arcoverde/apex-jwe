/**
 * @description Behavior of the JWK parser: which members are required, which are optional,
 * which are ignored, and what each one converts to.
 */
@IsTest(isParallel=true)
private class JweKeyTest {
    @IsTest
    static void readsThePublicMembers() {
        JweKey key = JweTestKeys.rsaPublicKey();

        Assert.areEqual(256, key.modulusOctets(), 'A 2048 bit modulus is 256 octets');
        Assert.areEqual(
            JweBigInt.valueOf(65537),
            key.publicExponent(),
            'AQAB is the base64url form of 65537, the usual public exponent'
        );
        Assert.isFalse(key.hasPrivateExponent(), 'A public key cannot decrypt');
        Assert.isFalse(key.hasCrtParameters(), 'A public key has no factors');
    }

    @IsTest
    static void readsThePrivateMembers() {
        JweKey key = JweTestKeys.rsaPrivateKey();

        Assert.isTrue(key.hasPrivateExponent(), 'The full key carries d');
        Assert.isTrue(key.hasCrtParameters(), 'The full key carries p, q, dp, dq and qi');

        JweBigInt.CrtParameters crt = key.crtParameters();

        Assert.isTrue(
            crt.p.isLessThan(key.modulus()) && crt.q.isLessThan(key.modulus()),
            'Both factors are smaller than the modulus they multiply to'
        );
        Assert.isTrue(
            key.privateExponent().isLessThan(key.modulus()),
            'The private exponent is reduced modulo the totient, so it is below the modulus'
        );
    }

    @IsTest
    static void treatsTheCrtMembersAsAllOrNothing() {
        JweKey key = JweTestKeys.rsaPrivateKeyWithoutCrt();

        Assert.isTrue(key.hasPrivateExponent(), 'The key still carries d');
        Assert.isFalse(key.hasCrtParameters(), 'A key missing every CRT member has none');

        String partialCrt = '{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB","p":"AQAB","q":"AQAB"}';

        Assert.isFalse(
            JweKey.fromJson(partialCrt).hasCrtParameters(),
            'Two of the five CRT members are not enough to take the CRT path'
        );
    }

    @IsTest
    static void ignoresMembersTheLibraryDoesNotUse() {
        String annotated =
            '{"kty":"RSA","use":"enc","key_ops":["unwrapKey"],"alg":"RSA-OAEP-256",' +
            '"kid":"2026-09","n":"AQAB","e":"AQAB"}';

        JweKey key = JweKey.fromJson(annotated);

        Assert.areEqual(
            JweBigInt.valueOf(65537),
            key.publicExponent(),
            'A key published with metadata for a wider purpose still parses'
        );
    }

    @IsTest
    static void requiresAKeyTypeThisLibraryUses() {
        for (
            String json : new List<String>{
                '{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB"}',
                '{"kty":"OKP","crv":"X25519","x":"AQAB"}',
                '{"n":"AQAB","e":"AQAB"}'
            }
        ) {
            try {
                JweKey.fromJson(json);
                Assert.fail('Only RSA and oct keys are supported: ' + json);
            } catch (JweException e) {
                Assert.isTrue(
                    e.getMessage().startsWith('Only RSA and oct keys are supported'),
                    'Failure names the cause, got: ' + e.getMessage()
                );
            }
        }
    }

    @IsTest
    static void readsASymmetricKeyFromAJwk() {
        // RFC 7518 §6.4: a shared key is a JWK of type oct whose k member carries the octets.
        String secretHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
        String keyJson =
            '{"kty":"oct","alg":"A256CBC-HS512","k":"' +
            JweBase64Url.encode(EncodingUtil.convertFromHex(secretHex)) +
            '"}';

        JweKey key = JweKey.fromJson(keyJson);

        Assert.isTrue(key.isSymmetric(), 'An oct key is symmetric');
        Assert.areEqual(
            secretHex,
            EncodingUtil.convertToHex(key.secret()),
            'The octets of k are the key material'
        );
    }

    @IsTest
    static void readsASymmetricKeyFromHex() {
        String secretHex = '000102030405060708090a0b0c0d0e0f';

        JweKey key = JweKey.fromSecretHex(secretHex);

        Assert.isTrue(key.isSymmetric(), 'A key built from hex is symmetric');
        Assert.areEqual(
            secretHex,
            EncodingUtil.convertToHex(key.secret()),
            'Hex and the k member describe the same octets'
        );
        Assert.isFalse(JweTestKeys.rsaPublicKey().isSymmetric(), 'An RSA key is not symmetric');
    }

    @IsTest
    static void requiresTheSecretOfASymmetricKey() {
        for (String keyJson : new List<String>{ '{"kty":"oct"}', '{"kty":"oct","k":""}' }) {
            try {
                JweKey.fromJson(keyJson);
                Assert.fail('An oct key without k carries nothing: ' + keyJson);
            } catch (JweException e) {
                Assert.areEqual(
                    'An oct key requires the member k',
                    e.getMessage(),
                    'Failure names the member'
                );
            }
        }

        try {
            JweKey.fromJson('{"kty":"oct","k":"AQ+B"}');
            Assert.fail('A secret outside the base64url alphabet must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Base64URL input has a character outside the alphabet',
                e.getMessage(),
                'The key fails while it is being built, not in the middle of an encryption'
            );
        }

        try {
            JweKey.fromSecretHex(null);
            Assert.fail('A null shared key must be rejected');
        } catch (JweException e) {
            Assert.areEqual('The shared key cannot be null', e.getMessage(), 'Null shared key');
        }
    }

    @IsTest
    static void keepsTheTwoKindsOfKeyApart() {
        JweKey symmetric = JweKey.fromSecretHex('000102030405060708090a0b0c0d0e0f');
        JweKey rsa = JweTestKeys.rsaPublicKey();

        for (String member : new List<String>{ 'modulus', 'exponent', 'octets' }) {
            try {
                if (member == 'modulus') {
                    symmetric.modulusOctets();
                } else if (member == 'exponent') {
                    symmetric.publicExponent();
                } else {
                    rsa.secret();
                }

                Assert.fail('A key must not answer for the other kind: ' + member);
            } catch (JweException e) {
                Assert.isTrue(
                    e.getMessage().startsWith('This is '),
                    'Failure says which kind of key it is, got: ' + e.getMessage()
                );
            }
        }
    }

    @IsTest
    static void requiresTheModulusAndThePublicExponent() {
        for (
            String json : new List<String>{
                '{"kty":"RSA","e":"AQAB"}',
                '{"kty":"RSA","n":"AQAB"}',
                '{"kty":"RSA","n":"","e":"AQAB"}',
                '{"kty":"RSA"}'
            }
        ) {
            try {
                JweKey.fromJson(json);
                Assert.fail('An RSA key without n and e is unusable: ' + json);
            } catch (JweException e) {
                Assert.areEqual(
                    'An RSA key requires the members n and e',
                    e.getMessage(),
                    'Failure names the missing members for: ' + json
                );
            }
        }
    }

    @IsTest
    static void rejectsMalformedJson() {
        for (String json : new List<String>{ '[{"kty":"RSA"}]', '"RSA"', '42' }) {
            try {
                JweKey.fromJson(json);
                Assert.fail('A JWK must be a JSON object: ' + json);
            } catch (JweException e) {
                Assert.areEqual(
                    'Key JSON is not a JSON object',
                    e.getMessage(),
                    'Failure names the cause for: ' + json
                );
            }
        }

        for (String json : new List<String>{ null, '', '   ' }) {
            try {
                JweKey.fromJson(json);
                Assert.fail('Missing key JSON must be rejected');
            } catch (JweException e) {
                Assert.areEqual(
                    'Key JSON cannot be blank',
                    e.getMessage(),
                    'Failure names the cause'
                );
            }
        }
    }

    @IsTest
    static void rejectsMembersThatAreNotStrings() {
        try {
            JweKey.fromJson('{"kty":"RSA","n":65537,"e":"AQAB"}');
            Assert.fail('A numeric modulus is not a JWK member');
        } catch (JweException e) {
            Assert.areEqual(
                'Key member n must be a string',
                e.getMessage(),
                'Failure names the member'
            );
        }
    }

    @IsTest
    static void rejectsMembersThatAreNotBase64Url() {
        try {
            JweKey.fromJson('{"kty":"RSA","n":"AQ+B","e":"AQAB"}');
            Assert.fail('A modulus outside the base64url alphabet must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Base64URL input has a character outside the alphabet',
                e.getMessage(),
                'The base64url decoder reports the cause'
            );
        }
    }

    @IsTest
    static void refusesToInventMissingPrivateMembers() {
        JweKey publicKey = JweTestKeys.rsaPublicKey();

        try {
            publicKey.privateExponent();
            Assert.fail('A public key has no private exponent to return');
        } catch (JweException e) {
            Assert.areEqual('The key carries no private exponent d', e.getMessage(), 'Missing d');
        }

        try {
            publicKey.crtParameters();
            Assert.fail('A public key has no CRT members to return');
        } catch (JweException e) {
            Assert.areEqual(
                'The key carries no CRT members p, q, dp, dq and qi',
                e.getMessage(),
                'Missing CRT members'
            );
        }
    }

    @IsTest
    static void keepsTheDeclaredModulusLength() {
        // A modulus whose first octet is zero: its value fits in fewer octets than the JWK
        // declares, and RSA lengths follow the declaration, not the value.
        String paddedModulus = JweBase64Url.encode(
            EncodingUtil.convertFromHex('00' + '01'.repeat(255))
        );

        JweKey key = JweKey.fromJson('{"kty":"RSA","n":"' + paddedModulus + '","e":"AQAB"}');

        Assert.areEqual(
            256,
            key.modulusOctets(),
            'The octet length comes from the encoded member, not from the integer'
        );
    }
}
