/**
 * @description Behavior of the byte string type. The I2OSP cases are the RFC 8017 §4.1
 * examples; everything else pins the contract the cryptographic primitives rely on: fixed
 * sizes, explicit failures and no silent truncation.
 */
@IsTest(isParallel=true)
private class JweBytesTest {
    @IsTest
    static void readsAndWritesHex() {
        JweBytes bytes = JweBytes.ofHex('00FF10a5');

        Assert.areEqual(4, bytes.size(), 'Two hex digits make one octet');
        Assert.areEqual(0, bytes.at(0), 'First octet');
        Assert.areEqual(255, bytes.at(1), 'Octets are unsigned');
        Assert.areEqual(165, bytes.at(3), 'Hex input is case insensitive');
        Assert.areEqual('00ff10a5', bytes.toHex(), 'Hex output is lower case');
    }

    @IsTest
    static void readsAndWritesBlobs() {
        Blob data = EncodingUtil.convertFromHex('0a0b0c');

        JweBytes bytes = JweBytes.of(data);

        Assert.areEqual('0a0b0c', bytes.toHex(), 'Blob octets are read in order');
        Assert.areEqual(
            EncodingUtil.convertToHex(data),
            EncodingUtil.convertToHex(bytes.toBlob()),
            'Round trip through Blob preserves the octets'
        );
    }

    @IsTest
    static void handlesEmptyByteStrings() {
        JweBytes empty = JweBytes.empty();

        Assert.areEqual(0, empty.size(), 'The empty byte string has no octets');
        Assert.areEqual('', empty.toHex(), 'The empty byte string has no hex digits');
        Assert.areEqual(
            0,
            empty.toBlob().size(),
            'The empty byte string converts to an empty blob'
        );
        Assert.areEqual(0, JweBytes.ofHex('').size(), 'An empty hex string reads as no octets');
    }

    @IsTest
    static void keepsOnlyTheLowOctetOfEachValue() {
        JweBytes bytes = JweBytes.ofValues(new List<Integer>{ 257, 255, 0, -1 });

        Assert.areEqual('01ff00ff', bytes.toHex(), 'Values are masked to one octet');
    }

    @IsTest
    static void concatenatesInOrder() {
        JweBytes joined = JweBytes.concat(
            new List<JweBytes>{ JweBytes.ofHex('01'), JweBytes.empty(), JweBytes.ofHex('0203') }
        );

        Assert.areEqual('010203', joined.toHex(), 'Parts are joined in order');
    }

    @IsTest
    static void rejectsNullPartsInConcatenation() {
        try {
            JweBytes.concat(new List<JweBytes>{ JweBytes.ofHex('01'), null });
            Assert.fail('A null part must be rejected instead of skipped');
        } catch (JweException e) {
            Assert.areEqual(
                'Parts to concatenate cannot contain null',
                e.getMessage(),
                'Failure names the cause'
            );
        }
    }

    @IsTest
    static void copiesSegments() {
        JweBytes bytes = JweBytes.ofHex('0a141e28');

        Assert.areEqual('141e', bytes.slice(1, 3).toHex(), 'End index is excluded');
        Assert.areEqual('', bytes.slice(2, 2).toHex(), 'An empty range yields no octets');
        Assert.areEqual('0a141e28', bytes.slice(0, 4).toHex(), 'The full range is a copy');
    }

    @IsTest
    static void rejectsSegmentsOutsideTheByteString() {
        JweBytes bytes = JweBytes.ofHex('0a141e28');

        try {
            bytes.slice(3, 1);
            Assert.fail('An inverted range must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Slice end is before its start', e.getMessage(), 'Inverted range');
        }

        try {
            bytes.slice(0, 5);
            Assert.fail('A range past the end must be rejected instead of truncated');
        } catch (JweException e) {
            Assert.isTrue(
                e.getMessage().contains('outside a 4 byte string'),
                'Failure states the available size, got: ' + e.getMessage()
            );
        }
    }

    @IsTest
    static void combinesOctetsWithXor() {
        JweBytes left = JweBytes.ofHex('ff0f');

        Assert.areEqual('f000', left.xor(JweBytes.ofHex('0f0f')).toHex(), 'XOR is per octet');
        Assert.areEqual(
            'ff0f',
            left.xor(JweBytes.ofHex('0f0f')).xor(JweBytes.ofHex('0f0f')).toHex(),
            'XOR with the same mask twice is the identity, which is how OAEP unmasks'
        );
    }

    @IsTest
    static void rejectsXorBetweenDifferentSizes() {
        try {
            JweBytes.ofHex('ff0f').xor(JweBytes.ofHex('ff'));
            Assert.fail('A size mismatch must be rejected instead of padded');
        } catch (JweException e) {
            Assert.areEqual(
                'XOR operands differ in size: 2 and 1',
                e.getMessage(),
                'Failure states both sizes'
            );
        }
    }

    @IsTest
    static void findsTheFirstOccurrenceOfAnOctet() {
        JweBytes bytes = JweBytes.ofHex('00050005');

        Assert.areEqual(1, bytes.indexOf(5, 0), 'First occurrence from the start');
        Assert.areEqual(3, bytes.indexOf(5, 2), 'First occurrence after the given position');
        Assert.areEqual(-1, bytes.indexOf(9, 0), 'An absent octet yields -1');
        Assert.areEqual(-1, bytes.indexOf(5, 4), 'A position past the end yields -1');
    }

    @IsTest
    static void buildsZeroedByteStrings() {
        Assert.areEqual('000000', JweBytes.zeros(3).toHex(), 'Three zeroed octets');
        Assert.areEqual('', JweBytes.zeros(0).toHex(), 'Zero octets are allowed');
    }

    @IsTest
    static void buildsRandomByteStringsOfTheRequestedSize() {
        // 48 crosses the 32-byte draw of the platform CSPRNG, so it also covers the case
        // where more than one draw is needed and the result has to be trimmed.
        JweBytes first = JweBytes.random(48);
        JweBytes second = JweBytes.random(48);

        Assert.areEqual(48, first.size(), 'Exactly the requested number of octets');
        Assert.areEqual(16, JweBytes.random(16).size(), 'A single draw covers 16 octets');
        Assert.areEqual(0, JweBytes.random(0).size(), 'Zero octets are allowed');
        Assert.isFalse(first.equals(second), 'Two draws must not produce the same octets');
    }

    @IsTest
    static void convertsIntegersToFourOctets() {
        Assert.areEqual('00000000', JweBytes.i2osp4(0).toHex(), 'RFC 8017 §4.1 with x = 0');
        Assert.areEqual('00000001', JweBytes.i2osp4(1).toHex(), 'RFC 8017 §4.1 with x = 1');
        Assert.areEqual('000001f4', JweBytes.i2osp4(500).toHex(), 'RFC 8017 §4.1 with x = 500');
        Assert.areEqual(
            '7fffffff',
            JweBytes.i2osp4(2147483647).toHex(),
            'The largest Apex Integer still fits in four octets'
        );
    }

    @IsTest
    static void comparesByValue() {
        JweBytes bytes = JweBytes.ofHex('010203');

        Assert.isTrue(bytes.equals(JweBytes.ofHex('010203')), 'Same octets are equal');
        Assert.isFalse(bytes.equals(JweBytes.ofHex('0102')), 'A prefix is not equal');
        Assert.isFalse(bytes.equals(null), 'Nothing equals null');
        Assert.isFalse(bytes.equals('010203'), 'A hex string is not a byte string');
        Assert.areEqual(
            JweBytes.ofHex('010203').hashCode(),
            bytes.hashCode(),
            'Equal byte strings must share a hash code'
        );
    }

    @IsTest
    static void comparesTagsInConstantTime() {
        JweBytes tag = JweBytes.ofHex('4dd3b4c088a7f45c');

        Assert.isTrue(
            tag.equalsConstantTime(JweBytes.ofHex('4dd3b4c088a7f45c')),
            'An identical tag is accepted'
        );
        Assert.isFalse(
            tag.equalsConstantTime(JweBytes.ofHex('4dd3b4c088a7f45d')),
            'A tag differing in the last octet is rejected'
        );
        Assert.isFalse(
            tag.equalsConstantTime(JweBytes.ofHex('5dd3b4c088a7f45c')),
            'A tag differing in the first octet is rejected'
        );
        Assert.isFalse(
            tag.equalsConstantTime(JweBytes.ofHex('4dd3b4c088a7f4')),
            'A truncated tag is rejected'
        );
        Assert.isFalse(tag.equalsConstantTime(null), 'A missing tag is rejected');
    }

    @IsTest
    static void rejectsMalformedHex() {
        try {
            JweBytes.ofHex('abc');
            Assert.fail('An odd number of digits must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Hex source must have an even number of digits',
                e.getMessage(),
                'Odd length'
            );
        }

        try {
            JweBytes.ofHex('0g');
            Assert.fail('A character outside the hex alphabet must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Hex source has a character outside the hex alphabet',
                e.getMessage(),
                'Invalid digit'
            );
        }
    }

    @IsTest
    static void rejectsMissingInput() {
        try {
            JweBytes.of((Blob) null);
            Assert.fail('A null blob must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Byte source cannot be null', e.getMessage(), 'Null blob');
        }

        try {
            JweBytes.ofHex(null);
            Assert.fail('A null hex string must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Hex source cannot be null', e.getMessage(), 'Null hex');
        }

        try {
            JweBytes.zeros(-1);
            Assert.fail('A negative length must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Byte length must be a non-negative integer',
                e.getMessage(),
                'Negative length'
            );
        }

        try {
            JweBytes.i2osp4(-1);
            Assert.fail('A negative integer has no I2OSP representation');
        } catch (JweException e) {
            Assert.areEqual(
                'I2OSP input must be a non-negative integer',
                e.getMessage(),
                'Negative I2OSP input'
            );
        }
    }

    @IsTest
    static void rejectsMissingByteStringArguments() {
        try {
            JweBytes.ofValues(null);
            Assert.fail('A null list of values must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Byte values cannot be null', e.getMessage(), 'Null list');
        }

        try {
            JweBytes.ofValues(new List<Integer>{ 1, null });
            Assert.fail('A null value inside the list must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Byte values cannot contain null',
                e.getMessage(),
                'Null value in the list'
            );
        }

        try {
            JweBytes.concat(null);
            Assert.fail('A null list of parts must be rejected');
        } catch (JweException e) {
            Assert.areEqual(
                'Parts to concatenate cannot be null',
                e.getMessage(),
                'Null list of parts'
            );
        }

        try {
            JweBytes.ofHex('0102').slice(null, 1);
            Assert.fail('A null slice bound must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Slice bounds cannot be null', e.getMessage(), 'Null slice bound');
        }

        try {
            JweBytes.ofHex('0102').xor(null);
            Assert.fail('A null XOR operand must be rejected');
        } catch (JweException e) {
            Assert.areEqual('XOR operand cannot be null', e.getMessage(), 'Null XOR operand');
        }
    }

    @IsTest
    static void rejectsOctetPositionsOutsideTheByteString() {
        JweBytes bytes = JweBytes.ofHex('0102');

        try {
            bytes.at(2);
            Assert.fail('A position past the end must be rejected');
        } catch (JweException e) {
            Assert.areEqual('Byte index out of range: 2', e.getMessage(), 'Out of range position');
        }
    }
}
