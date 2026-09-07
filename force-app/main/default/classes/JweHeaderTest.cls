/**
 * @description Behavior of the protected header. The canonical serialization is pinned against
 * headers produced by an external JOSE library, which is the only way to know that what this
 * class authenticates is what the rest of the world writes.
 */
@IsTest(isParallel=true)
private class JweHeaderTest {
    // First part of two tokens generated with jose (Node), the same ones embedded in
    // JweInteropVectorsTest.
    private static final String DIR_A128_HEADER = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiaW50ZXJvcC01In0';
    private static final String RSA_OAEP_256_A256_HEADER = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiaW50ZXJvcC0zIn0';

    @IsTest
    static void serializesItsMembersInCanonicalOrder() {
        Assert.areEqual(
            '{"alg":"dir","enc":"A256CBC-HS512"}',
            new JweHeader('dir', 'A256CBC-HS512').toJson(),
            'A header without a key identifier carries two members'
        );
        Assert.areEqual(
            '{"alg":"RSA-OAEP-256","enc":"A256CBC-HS512","kid":"2026-09"}',
            new JweHeader('RSA-OAEP-256', 'A256CBC-HS512').withKeyId('2026-09').toJson(),
            'The key identifier comes last, after alg and enc'
        );
    }

    @IsTest
    static void encodesLikeAnExternalJoseLibrary() {
        Assert.areEqual(
            DIR_A128_HEADER,
            new JweHeader('dir', 'A128CBC-HS256').withKeyId('interop-5').encode(),
            'The encoded header must match the one jose produced for the same members'
        );
        Assert.areEqual(
            RSA_OAEP_256_A256_HEADER,
            new JweHeader('RSA-OAEP-256', 'A256CBC-HS512').withKeyId('interop-3').encode(),
            'Same for the RSA-OAEP-256 token'
        );
    }

    @IsTest
    static void parsesTheHeaderOfARealToken() {
        JweHeader header = JweHeader.parse(RSA_OAEP_256_A256_HEADER);

        Assert.areEqual('RSA-OAEP-256', header.alg(), 'The key management algorithm');
        Assert.areEqual('A256CBC-HS512', header.enc(), 'The content encryption algorithm');
        Assert.areEqual('interop-3', header.keyId(), 'The key identifier');
    }

    @IsTest
    static void roundTripsThroughEncoding() {
        JweHeader original = new JweHeader('dir', 'A128CBC-HS256').withKeyId('interop-5');

        JweHeader parsed = JweHeader.parse(original.encode());

        Assert.isTrue(original.hasSameAlgorithms(parsed), 'The algorithms survive the round trip');
        Assert.areEqual(original.keyId(), parsed.keyId(), 'The key identifier survives too');
    }

    @IsTest
    static void acceptsAHeaderWithoutAKeyIdentifier() {
        JweHeader parsed = JweHeader.parse(
            JweBase64Url.encode(Blob.valueOf('{"alg":"dir","enc":"A128CBC-HS256"}'))
        );

        Assert.isNull(parsed.keyId(), 'kid is optional');
    }

    @IsTest
    static void writesTheKeyIdentifierAsDataAndNotAsMarkup() {
        // A key identifier chosen to close the JSON string and open a second alg member. Built
        // with a template it would produce a header claiming alg none; built with a JSON
        // generator it stays one value.
        String hostileKeyId = 'a","alg":"none';

        JweHeader header = new JweHeader('RSA-OAEP-256', 'A256CBC-HS512').withKeyId(hostileKeyId);
        JweHeader parsed = JweHeader.parse(header.encode());

        Assert.areEqual(
            '{"alg":"RSA-OAEP-256","enc":"A256CBC-HS512","kid":"a\\",\\"alg\\":\\"none"}',
            header.toJson(),
            'The quotes of the key identifier are escaped'
        );
        Assert.areEqual('RSA-OAEP-256', parsed.alg(), 'The algorithm is still the configured one');
        Assert.areEqual(hostileKeyId, parsed.keyId(), 'The key identifier is returned verbatim');
    }

    @IsTest
    static void comparesAlgorithmsCaseSensitively() {
        JweHeader configured = new JweHeader('RSA-OAEP-256', 'A256CBC-HS512');

        Assert.isTrue(
            configured.hasSameAlgorithms(new JweHeader('RSA-OAEP-256', 'A256CBC-HS512')),
            'The same pair of algorithms matches'
        );
        Assert.isTrue(
            configured.hasSameAlgorithms(
                new JweHeader('RSA-OAEP-256', 'A256CBC-HS512').withKeyId('another-key')
            ),
            'The key identifier says which key, not which algorithm'
        );
        Assert.isFalse(
            configured.hasSameAlgorithms(new JweHeader('RSA-OAEP', 'A256CBC-HS512')),
            'A different key management algorithm does not match'
        );
        Assert.isFalse(
            configured.hasSameAlgorithms(new JweHeader('RSA-OAEP-256', 'A128CBC-HS256')),
            'A different content encryption does not match'
        );
        Assert.isFalse(
            configured.hasSameAlgorithms(new JweHeader('rsa-oaep-256', 'a256cbc-hs512')),
            'RFC 7515 §4.1.1 makes header values case sensitive, and Apex string equality is not'
        );
        Assert.isFalse(configured.hasSameAlgorithms(null), 'A missing header does not match');
    }

    @IsTest
    static void keepsInstancesImmutable() {
        JweHeader original = new JweHeader('dir', 'A128CBC-HS256');

        JweHeader named = original.withKeyId('2026-09');

        Assert.isNull(original.keyId(), 'The original header is unchanged');
        Assert.areEqual('2026-09', named.keyId(), 'The copy carries the key identifier');
        Assert.areEqual(
            '{"alg":"dir","enc":"A128CBC-HS256"}',
            original.toJson(),
            'And it still serializes without a kid member'
        );
    }

    @IsTest
    static void requiresBothAlgorithms() {
        for (String alg : new List<String>{ null, '', '  ' }) {
            try {
                new JweHeader(alg, 'A128CBC-HS256');
                Assert.fail('A header without alg is not a header');
            } catch (JweException e) {
                Assert.areEqual(
                    'The header member alg cannot be blank',
                    e.getMessage(),
                    'Failure names the member'
                );
            }
        }

        try {
            new JweHeader('dir', null);
            Assert.fail('A header without enc is not a header');
        } catch (JweException e) {
            Assert.areEqual(
                'The header member enc cannot be blank',
                e.getMessage(),
                'Failure names the member'
            );
        }
    }

    @IsTest
    static void rejectsHeadersMissingTheirAlgorithms() {
        Map<String, String> cases = new Map<String, String>{
            '{"enc":"A128CBC-HS256"}' => 'The header member alg cannot be blank',
            '{"alg":"dir"}' => 'The header member enc cannot be blank',
            '{}' => 'The header member alg cannot be blank'
        };

        for (String text : cases.keySet()) {
            try {
                JweHeader.parse(JweBase64Url.encode(Blob.valueOf(text)));
                Assert.fail('Must be rejected: ' + text);
            } catch (JweException e) {
                Assert.areEqual(cases.get(text), e.getMessage(), 'Failure names the member');
            }
        }
    }

    @IsTest
    static void rejectsExtensionsItDoesNotImplement() {
        // RFC 7516 §5.2 step 5: crit exists to say that ignoring a member is not acceptable.
        // zip would hand back a plaintext that is still deflated.
        try {
            JweHeader.parse(
                JweBase64Url.encode(
                    Blob.valueOf(
                        '{"alg":"dir","enc":"A128CBC-HS256","crit":["exp"],"exp":1893456000}'
                    )
                )
            );
            Assert.fail('A critical header member must not be ignored');
        } catch (JweException e) {
            Assert.areEqual(
                'The header requires extensions this library does not implement',
                e.getMessage(),
                'Failure names the cause'
            );
        }

        try {
            JweHeader.parse(
                JweBase64Url.encode(Blob.valueOf('{"alg":"dir","enc":"A128CBC-HS256","zip":"DEF"}'))
            );
            Assert.fail('A compressed payload must not be returned deflated');
        } catch (JweException e) {
            Assert.areEqual(
                'Compressed payloads are not supported',
                e.getMessage(),
                'Failure names the cause'
            );
        }
    }

    @IsTest
    static void rejectsHeadersThatAreNotJsonObjects() {
        for (String text : new List<String>{ '["dir"]', '"dir"', '42', 'not json at all' }) {
            try {
                JweHeader.parse(JweBase64Url.encode(Blob.valueOf(text)));
                Assert.fail('A header must be a JSON object: ' + text);
            } catch (JweException e) {
                Assert.areEqual(
                    'The header is not a JSON object',
                    e.getMessage(),
                    'Failure names the cause for: ' + text
                );
            }
        }
    }

    @IsTest
    static void rejectsMembersThatAreNotStrings() {
        try {
            JweHeader.parse(
                JweBase64Url.encode(Blob.valueOf('{"alg":"dir","enc":"A128CBC-HS256","kid":7}'))
            );
            Assert.fail('A numeric key identifier is not a JOSE header member');
        } catch (JweException e) {
            Assert.areEqual(
                'The header member kid must be a string',
                e.getMessage(),
                'Failure names the member'
            );
        }
    }

    @IsTest
    static void rejectsHeadersThatAreNotBase64Url() {
        for (String encoded : new List<String>{ null, 'not base64url!', 'eyJhbGciOiJkaXIif' }) {
            Boolean rejected = false;

            try {
                JweHeader.parse(encoded);
            } catch (JweException e) {
                rejected = true;
            }

            Assert.isTrue(rejected, 'The header part must be valid base64url: ' + encoded);
        }
    }
}
