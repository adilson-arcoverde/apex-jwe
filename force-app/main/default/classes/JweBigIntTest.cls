/**
 * @description Arithmetic of the RSA layer, verified against number theory instead of against
 * the padding scheme built on top of it: known modular exponentiation results, and a small RSA
 * key pair whose ciphertext for a fixed message is known.
 *
 * The key below is 512 bits, small enough to exercise both the private exponent path and the
 * CRT path inside one test without approaching the CPU limit, and large enough to require
 * multi-digit arithmetic. It is not a security key and is never used to protect anything.
 */
@IsTest(isParallel=true)
private class JweBigIntTest {
    // Generated on 2026-09-07 with Python (seeded Miller-Rabin). Documented in
    // docs/TEST-VECTORS.md. Throwaway key: 512 bit RSA is not secure and is used here only
    // because the arithmetic is the same at any size.
    private static final String N =
        'ae6d141129b984af2852e77ff1e1fd1b837ba94b11685924a12c3b7780d7ab98' +
        'a3c0eab57d5e00af2c4981e880e219b3c3d2f0dd896ac2ba964e622342a8493b';
    private static final String E = '10001';
    private static final String D =
        'a5f923442598e339acbc1e8eaf8263ceff70f7297839fbc110203fc1b9f6fece' +
        'dd817db8709d9b8d46d2874f8d2958eeaf3e3b48ebe02e62a1066990e6bbba81';
    private static final String P = 'ba492733ccc1dbe73542d01469285f7130692184e927139838f9a6e1eda1ea7b';
    private static final String Q = 'efb3b9f55695910ac531dd17954b2af75d7297bee57f3a5b3c406dde3cb74041';
    private static final String DP = '7cdcfbc1e4c52c38d5a26b06c355a463a22755a858ff304b2025768e8951b671';
    private static final String DQ = '6abbbeac0df7df73ca46dfc9e682680969a4e308efabed523ecbf9a021acff81';
    private static final String QI = 'b193310124618fbe7dd622a6bee42da1d4c837c4e6b2c0cdb65cfb9fde4ad9cc';
    private static final String M = '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
    private static final String C =
        'a0864bdbd09b2040c756bab4d2006148b1ff7f3e0b947f22f24008ca028951df' +
        'b8fe387c80ea16b19c8825a24af8149cb8bb0c3f2896eddd10683c6c4faf43ce';
    private static final Integer K = 64;

    @IsTest
    static void raisesToAPowerModuloASmallNumber() {
        Assert.areEqual(
            JweBigInt.valueOf(445),
            JweBigInt.valueOf(4).modPow(JweBigInt.valueOf(13), JweBigInt.valueOf(497)),
            '4^13 mod 497 = 445, the textbook square and multiply example'
        );
        Assert.areEqual(
            JweBigInt.valueOf(688423210),
            JweBigInt.valueOf(2).modPow(JweBigInt.valueOf(1000), JweBigInt.valueOf(1000000007)),
            '2^1000 mod 1000000007 = 688423210, an exponent wider than the modulus'
        );
        Assert.areEqual(
            JweBigInt.valueOf(1),
            JweBigInt.valueOf(7).modPow(JweBigInt.valueOf(0), JweBigInt.valueOf(13)),
            'Any base raised to zero is one'
        );
        Assert.areEqual(
            JweBigInt.valueOf(0),
            JweBigInt.valueOf(0).modPow(JweBigInt.valueOf(5), JweBigInt.valueOf(13)),
            'Zero raised to a positive power is zero'
        );
    }

    @IsTest
    static void appliesTheRsaPublicExponent() {
        JweBigInt cipher = JweBigInt.fromHex(M).modPow(JweBigInt.fromHex(E), JweBigInt.fromHex(N));

        Assert.areEqual(C, cipher.toHex(K), 'm^e mod n must reproduce the published ciphertext');
    }

    @IsTest
    static void appliesTheRsaPrivateExponent() {
        JweBigInt message = JweBigInt.fromHex(C).modPow(JweBigInt.fromHex(D), JweBigInt.fromHex(N));

        Assert.areEqual(M, message.toHex(32), 'c^d mod n must recover the message');
    }

    @IsTest
    static void appliesThePrivateExponentThroughTheCrtPath() {
        JweBigInt.CrtParameters crt = crtParameters();

        JweBigInt message = JweBigInt.fromHex(C).modPowCrt(crt);

        Assert.areEqual(
            M,
            message.toHex(32),
            'The CRT path must agree with the private exponent path on the same ciphertext'
        );
    }

    @IsTest
    static void padsToTheModulusLength() {
        // A value whose most significant octets are zero: RSA requires the ciphertext to be
        // exactly as long as the modulus, so the leading zeros are part of the wire format.
        JweBigInt small = JweBigInt.valueOf(255);

        Assert.areEqual('ff', small.toHex(), 'The canonical form carries no leading zero octet');
        Assert.areEqual('00ff', small.toHex(2), 'I2OSP pads on the left');
        Assert.areEqual(
            K,
            small.toBlob(K).size(),
            'I2OSP to the modulus length always yields that many octets'
        );
        Assert.areEqual('00', JweBigInt.valueOf(0).toHex(), 'Zero is one zeroed octet');
        Assert.areEqual('0000', JweBigInt.valueOf(0).toHex(2), 'Zero pads like any other value');
        Assert.areEqual(
            '0102',
            JweBigInt.fromHex('0102').toHex(),
            'A leading zero nibble is kept: hex output always has full octets'
        );
    }

    @IsTest
    static void refusesToTruncate() {
        try {
            JweBigInt.fromHex(N).toHex(32);
            Assert.fail('A value wider than the requested length must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Integer is too large for 32 octets',
                e.getMessage(),
                'Silent truncation would corrupt a ciphertext'
            );
        }
    }

    @IsTest
    static void readsAndWritesOctetStrings() {
        Blob modulus = EncodingUtil.convertFromHex(N);

        JweBigInt value = JweBigInt.fromBytes(modulus);

        Assert.areEqual(
            N,
            EncodingUtil.convertToHex(value.toBlob(K)),
            'OS2IP followed by I2OSP is the identity on a fixed length octet string'
        );
        Assert.areEqual(
            JweBigInt.valueOf(0),
            JweBigInt.fromBytes(EncodingUtil.convertFromHex('')),
            'An empty octet string reads as zero'
        );
        Assert.areEqual(JweBigInt.valueOf(0), JweBigInt.fromHex(''), 'Empty hex reads as zero');
    }

    @IsTest
    static void reducesModuloAnotherInteger() {
        Assert.areEqual(
            JweBigInt.valueOf(4),
            JweBigInt.valueOf(25).mod(JweBigInt.valueOf(7)),
            '25 mod 7 = 4'
        );
        Assert.areEqual(
            JweBigInt.valueOf(0),
            JweBigInt.valueOf(28).mod(JweBigInt.valueOf(7)),
            'An exact multiple reduces to zero'
        );
        Assert.areEqual(
            JweBigInt.fromHex(C),
            JweBigInt.fromHex(C).mod(JweBigInt.fromHex(N)),
            'A ciphertext is already reduced modulo n'
        );
    }

    @IsTest
    static void comparesMagnitudes() {
        Assert.isTrue(
            JweBigInt.valueOf(254).isLessThan(JweBigInt.valueOf(255)),
            'A smaller integer is smaller'
        );
        Assert.isFalse(
            JweBigInt.valueOf(255).isLessThan(JweBigInt.valueOf(255)),
            'An equal integer is not smaller'
        );
        Assert.isFalse(
            JweBigInt.valueOf(256).isLessThan(JweBigInt.valueOf(255)),
            'A larger integer is not smaller'
        );
        Assert.isTrue(
            JweBigInt.fromHex(C).isLessThan(JweBigInt.fromHex(N)),
            'A valid ciphertext representative is smaller than the modulus'
        );
        Assert.isFalse(
            JweBigInt.fromHex(N).isLessThan(JweBigInt.fromHex(N)),
            'The modulus itself is out of range as a ciphertext representative'
        );

        try {
            JweBigInt.valueOf(1).isLessThan(null);
            Assert.fail('A null comparison operand must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Comparison operand cannot be null',
                e.getMessage(),
                'Null comparison operand'
            );
        }
    }

    @IsTest
    static void comparesByValue() {
        Assert.isTrue(
            JweBigInt.fromHex('ff').equals(JweBigInt.valueOf(255)),
            'The same number read from hex and from an integer is equal'
        );
        Assert.isTrue(
            JweBigInt.fromHex('00ff').equals(JweBigInt.fromHex('ff')),
            'Leading zeros do not change the value'
        );
        Assert.isFalse(JweBigInt.valueOf(255).equals(JweBigInt.valueOf(254)), 'Different values');
        Assert.isFalse(JweBigInt.valueOf(255).equals(null), 'Nothing equals null');
        Assert.isFalse(JweBigInt.valueOf(255).equals('ff'), 'A hex string is not an integer');
        Assert.areEqual(
            JweBigInt.valueOf(255).hashCode(),
            JweBigInt.fromHex('ff').hashCode(),
            'Equal integers must share a hash code'
        );
    }

    @IsTest
    static void rejectsInvalidArithmetic() {
        JweBigInt two = JweBigInt.valueOf(2);

        try {
            two.modPow(two, JweBigInt.valueOf(0));
            Assert.fail('A modulus of zero has no arithmetic');
        } catch (JweException e) {
            Assert.areEqual('Modulus must be positive', e.getMessage(), 'Zero modulus');
        }

        try {
            two.modPow(two, null);
            Assert.fail('A missing modulus must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Modulus cannot be null', e.getMessage(), 'Null modulus');
        }

        try {
            two.modPow(null, two);
            Assert.fail('A missing exponent must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Exponent cannot be null', e.getMessage(), 'Null exponent');
        }

        try {
            JweBigInt.valueOf(-1);
            Assert.fail('A negative value has no place in RSA arithmetic');
        } catch (JweException e) {
            Assert.areEqual(
                'Big integer value must be non-negative',
                e.getMessage(),
                'Negative value'
            );
        }

        try {
            JweBigInt.fromHex(null);
            Assert.fail('A null hex source must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Hex source cannot be null', e.getMessage(), 'Null hex source');
        }

        try {
            JweBigInt.fromBytes(null);
            Assert.fail('A null octet string must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Byte source cannot be null', e.getMessage(), 'Null octet string');
        }

        try {
            JweBigInt.fromHex('0x10');
            Assert.fail('A character outside the hex alphabet must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Hex source has a character outside the hex alphabet',
                e.getMessage(),
                'Invalid digit'
            );
        }

        try {
            JweBigInt.valueOf(1).toHex(-1);
            Assert.fail('A negative octet length must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Octet length must be a non-negative integer',
                e.getMessage(),
                'Negative octet length'
            );
        }
    }

    @IsTest
    static void rejectsIncompleteCrtParameters() {
        JweBigInt.CrtParameters crt = crtParameters();
        crt.qi = null;

        try {
            JweBigInt.fromHex(C).modPowCrt(crt);
            Assert.fail('An incomplete CRT key must be rejected instead of guessed');
        } catch (JweException e) {
            Assert.areEqual(
                'CRT parameters p, q, dp, dq and qi are all required',
                e.getMessage(),
                'Missing qi'
            );
        }

        try {
            JweBigInt.fromHex(C).modPowCrt(null);
            Assert.fail('Missing CRT parameters must be rejected');
        } catch (JweException e) {
            Assert.areEqual('CRT parameters cannot be null', e.getMessage(), 'Null CRT parameters');
        }
    }

    private static JweBigInt.CrtParameters crtParameters() {
        JweBigInt.CrtParameters crt = new JweBigInt.CrtParameters();
        crt.p = JweBigInt.fromHex(P);
        crt.q = JweBigInt.fromHex(Q);
        crt.dp = JweBigInt.fromHex(DP);
        crt.dq = JweBigInt.fromHex(DQ);
        crt.qi = JweBigInt.fromHex(QI);

        return crt;
    }
}
