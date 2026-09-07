/**
 * @description Base64URL encoding, pinned with the RFC 4648 §10 test vectors adapted to the
 * URL and filename safe alphabet without padding, which is the form RFC 7515 §2 requires.
 */
@IsTest(isParallel=true)
private class JweBase64UrlTest {
    // RFC 4648 §10, in order: the empty string and the six prefixes of 'foobar'.
    private static final List<String> PLAINTEXTS = new List<String>{
        '',
        'f',
        'fo',
        'foo',
        'foob',
        'fooba',
        'foobar'
    };
    private static final List<String> ENCODED = new List<String>{
        '',
        'Zg',
        'Zm8',
        'Zm9v',
        'Zm9vYg',
        'Zm9vYmE',
        'Zm9vYmFy'
    };

    @IsTest
    static void encodesTheRfc4648Vectors() {
        for (Integer i = 0; i < PLAINTEXTS.size(); i++) {
            Assert.areEqual(
                ENCODED[i],
                JweBase64Url.encode(Blob.valueOf(PLAINTEXTS[i])),
                'RFC 4648 §10 vector without padding: ' + PLAINTEXTS[i]
            );
        }
    }

    @IsTest
    static void decodesTheRfc4648Vectors() {
        for (Integer i = 0; i < ENCODED.size(); i++) {
            Assert.areEqual(
                PLAINTEXTS[i],
                JweBase64Url.decodeToText(ENCODED[i]),
                'RFC 4648 §10 vector decoded: ' + ENCODED[i]
            );
        }
    }

    @IsTest
    static void usesTheUrlSafeAlphabet() {
        // fb ff bf occupies the two code points where the two alphabets differ: standard
        // Base64 would encode it as '+/+/'.
        Blob highBytes = EncodingUtil.convertFromHex('fbffbf');

        Assert.areEqual(
            '-_-_',
            JweBase64Url.encode(highBytes),
            'Code points 62 and 63 are - and _'
        );
        Assert.areEqual(
            'fbffbf',
            EncodingUtil.convertToHex(JweBase64Url.decode('-_-_')),
            'The URL safe alphabet decodes back to the same octets'
        );
        Assert.areEqual(
            '+/+/',
            EncodingUtil.base64Encode(highBytes),
            'The platform encoder still uses the standard alphabet, which is why the translation exists'
        );
    }

    @IsTest
    static void roundTripsArbitraryOctets() {
        Blob key = EncodingUtil.convertFromHex(
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        );

        String encoded = JweBase64Url.encode(key);

        Assert.isFalse(encoded.contains('='), 'The encoding carries no padding');
        Assert.areEqual(
            EncodingUtil.convertToHex(key),
            EncodingUtil.convertToHex(JweBase64Url.decode(encoded)),
            'A 32 byte key survives the round trip'
        );
    }

    @IsTest
    static void rejectsCharactersOutsideTheAlphabet() {
        for (String encoded : new List<String>{ 'Zm9+', 'Zm9/', 'Zm 9v', 'Zm9v.', 'Zm9$' }) {
            try {
                JweBase64Url.decode(encoded);
                Assert.fail('Input outside the alphabet must be rejected: ' + encoded);
            } catch (JweException e) {
                Assert.areEqual(
                    'Base64URL input has a character outside the alphabet',
                    e.getMessage(),
                    'Failure names the cause for: ' + encoded
                );
            }
        }
    }

    @IsTest
    static void rejectsPadding() {
        try {
            JweBase64Url.decode('Zg==');
            Assert.fail('Padding is not part of the base64url form used by JWE');
        } catch (JweException e) {
            Assert.areEqual(
                'Base64URL input has a character outside the alphabet',
                e.getMessage(),
                'Padding is rejected as an alien character'
            );
        }
    }

    @IsTest
    static void rejectsLengthsNoOctetStringCanProduce() {
        try {
            JweBase64Url.decode('Zm9vYmFyZ');
            Assert.fail('A final quantum of one character encodes no octet');
        } catch (JweException e) {
            Assert.areEqual(
                'Base64URL input has an invalid length',
                e.getMessage(),
                'Failure names the cause'
            );
        }
    }

    @IsTest
    static void rejectsMissingInput() {
        try {
            JweBase64Url.encode((Blob) null);
            Assert.fail('A null blob must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Base64URL input cannot be null', e.getMessage(), 'Null blob');
        }

        try {
            JweBase64Url.decode(null);
            Assert.fail('A null string must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Base64URL input cannot be null', e.getMessage(), 'Null string');
        }
    }
}
