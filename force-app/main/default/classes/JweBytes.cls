/**
 * @description Immutable array of unsigned bytes. It is the transport format between the
 * cryptographic primitives of the library: OAEP encoding, MGF1 mask generation and the
 * AES-CBC + HMAC composition all work on byte positions, not on characters.
 *
 * Apex offers no indexed access to `Blob` and no unsigned byte type, so the octets are held
 * as a `List<Integer>` in the range 0-255 and hex is the only bridge to and from `Blob`
 * (`EncodingUtil.convertToHex` / `convertFromHex`). Instances never change after
 * construction: every operation returns a new instance, so a caller holding key material
 * cannot have it mutated underneath it.
 */
public inherited sharing class JweBytes {
    private static final String HEX_DIGITS = '0123456789abcdef';
    private static final Integer BITS_PER_NIBBLE = 4;
    private static final Integer NIBBLE_MASK = 15;
    private static final Integer OCTET_MASK = 255;

    /**
     * @description Size of each `Crypto.generateAesKey(256)` draw, in octets. The platform
     * CSPRNG is exposed as a key generator, so random octets are taken in 32-byte chunks.
     */
    private static final Integer RANDOM_CHUNK_OCTETS = 32;

    private final List<Integer> values;

    private JweBytes(List<Integer> values) {
        this.values = values;
    }

    /**
     * @description Returns an instance with no bytes.
     * @return The empty instance.
     */
    public static JweBytes empty() {
        return new JweBytes(new List<Integer>());
    }

    /**
     * @description Reads the octets of a blob.
     * @param data The blob to read.
     * @return The octets of the blob.
     * @throws JweException When data is null.
     */
    public static JweBytes of(Blob data) {
        if (data == null) {
            throw new JweException('Byte source cannot be null');
        }

        return ofHex(EncodingUtil.convertToHex(data));
    }

    /**
     * @description Reads octets from their hex representation, which is how `EncodingUtil`
     * and the RFC test vectors express byte strings.
     * @param hex The hex digits, upper or lower case, two per octet.
     * @return The decoded octets.
     * @throws JweException When hex is null, has an odd number of digits or carries a
     * character outside the hex alphabet.
     */
    public static JweBytes ofHex(String hex) {
        if (hex == null) {
            throw new JweException('Hex source cannot be null');
        }

        String normalized = hex.toLowerCase();

        if (Math.mod(normalized.length(), 2) != 0) {
            throw new JweException('Hex source must have an even number of digits');
        }

        Integer size = normalized.length() / 2;
        List<Integer> result = new List<Integer>(size);

        for (Integer i = 0; i < size; i++) {
            Integer high = nibbleAt(normalized, 2 * i);
            Integer low = nibbleAt(normalized, 2 * i + 1);
            result[i] = (high << BITS_PER_NIBBLE) | low;
        }

        return new JweBytes(result);
    }

    /**
     * @description Wraps a list of byte values, keeping only the low octet of each one.
     * @param byteValues The values to wrap.
     * @return The resulting octets.
     * @throws JweException When byteValues or any of its elements is null.
     */
    public static JweBytes ofValues(List<Integer> byteValues) {
        if (byteValues == null) {
            throw new JweException('Byte values cannot be null');
        }

        List<Integer> result = new List<Integer>(byteValues.size());

        for (Integer i = 0; i < byteValues.size(); i++) {
            if (byteValues[i] == null) {
                throw new JweException('Byte values cannot contain null');
            }

            result[i] = byteValues[i] & OCTET_MASK;
        }

        return new JweBytes(result);
    }

    /**
     * @description Returns the requested number of zeroed octets, the padding string PS of
     * EME-OAEP encoding.
     * @param length How many octets.
     * @return The zeroed octets.
     * @throws JweException When length is null or negative.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-7.1.1
     */
    public static JweBytes zeros(Integer length) {
        requireLength(length);

        List<Integer> result = new List<Integer>(length);

        for (Integer i = 0; i < length; i++) {
            result[i] = 0;
        }

        return new JweBytes(result);
    }

    /**
     * @description Returns the requested number of cryptographically random octets, used for
     * the OAEP seed, the content encryption key and the initialization vector.
     *
     * The source is `Crypto.generateAesKey`, not `Crypto.getRandomInteger`: the latter is
     * capped at 2^31-1, which would leave the top bit of every fourth octet at zero.
     * @param length How many octets.
     * @return The random octets.
     * @throws JweException When length is null or negative.
     */
    public static JweBytes random(Integer length) {
        requireLength(length);

        List<Integer> result = new List<Integer>();

        while (result.size() < length) {
            result.addAll(of(Crypto.generateAesKey(RANDOM_CHUNK_OCTETS * 8)).values);
        }

        JweBytes drawn = new JweBytes(result);

        return drawn.size() == length ? drawn : drawn.slice(0, length);
    }

    /**
     * @description I2OSP with a fixed output length of four octets, the counter format of
     * MGF1 and of the AL field of AES_CBC_HMAC_SHA2.
     * @param value The non-negative integer to convert.
     * @return The value as four octets, most significant first.
     * @throws JweException When value is null or negative.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-4.1
     */
    public static JweBytes i2osp4(Integer value) {
        if (value == null || value < 0) {
            throw new JweException('I2OSP input must be a non-negative integer');
        }

        return ofValues(new List<Integer>{ value >>> 24, value >>> 16, value >>> 8, value });
    }

    /**
     * @description Joins the given byte strings, in order.
     * @param parts The byte strings to join.
     * @return The concatenation.
     * @throws JweException When parts or any of its elements is null.
     */
    public static JweBytes concat(List<JweBytes> parts) {
        if (parts == null) {
            throw new JweException('Parts to concatenate cannot be null');
        }

        List<Integer> result = new List<Integer>();

        for (JweBytes part : parts) {
            if (part == null) {
                throw new JweException('Parts to concatenate cannot contain null');
            }

            result.addAll(part.values);
        }

        return new JweBytes(result);
    }

    /**
     * @description Returns how many octets this instance carries.
     * @return The octet count.
     */
    public Integer size() {
        return this.values.size();
    }

    /**
     * @description Returns the octet at the given position.
     * @param index The zero-based position.
     * @return The octet value, 0 to 255.
     * @throws JweException When index is outside the byte string.
     */
    public Integer at(Integer index) {
        if (index == null || index < 0 || index >= this.values.size()) {
            throw new JweException('Byte index out of range: ' + index);
        }

        return this.values[index];
    }

    /**
     * @description Returns the position of the first occurrence of an octet, at or after the
     * given position. EME-OAEP decoding uses it to find the 0x01 separator of DB.
     * @param value The octet to look for.
     * @param fromIndex The position to start from.
     * @return The position, or -1 when the octet does not occur.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-7.1.2
     */
    public Integer indexOf(Integer value, Integer fromIndex) {
        for (Integer i = Math.max(fromIndex, 0); i < this.values.size(); i++) {
            if (this.values[i] == value) {
                return i;
            }
        }

        return -1;
    }

    /**
     * @description Copies a segment of this byte string.
     * @param fromIndex The zero-based start position, included.
     * @param toIndex The zero-based end position, excluded.
     * @return The copied octets.
     * @throws JweException When the bounds are null, inverted or outside the byte string.
     */
    public JweBytes slice(Integer fromIndex, Integer toIndex) {
        requireBounds(fromIndex, toIndex);

        List<Integer> result = new List<Integer>(toIndex - fromIndex);

        for (Integer i = fromIndex; i < toIndex; i++) {
            result[i - fromIndex] = this.values[i];
        }

        return new JweBytes(result);
    }

    /**
     * @description Combines this byte string with another one, octet by octet, with XOR. It
     * is how MGF1 masks are applied and removed in EME-OAEP.
     * @param other The byte string to combine with. Must have the same size.
     * @return The result of the operation.
     * @throws JweException When other is null or of a different size.
     */
    public JweBytes xor(JweBytes other) {
        if (other == null) {
            throw new JweException('XOR operand cannot be null');
        }

        Integer n = this.values.size();

        if (other.values.size() != n) {
            throw new JweException(
                'XOR operands differ in size: ' + n + ' and ' + other.values.size()
            );
        }

        List<Integer> result = new List<Integer>(n);

        for (Integer i = 0; i < n; i++) {
            result[i] = this.values[i] ^ other.values[i];
        }

        return new JweBytes(result);
    }

    /**
     * @description Compares two byte strings in time that depends on their length, never on
     * their content. Required wherever an attacker controls one of the operands, which is the
     * case of the authentication tag of a received token: an early return on the first
     * mismatching octet would leak, through timing, how many leading octets were guessed
     * right.
     * @param other The byte string to compare with.
     * @return true when both have the same size and the same octets; otherwise false.
     * @see https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.2
     */
    public Boolean equalsConstantTime(JweBytes other) {
        if (other == null || other.values.size() != this.values.size()) {
            return false;
        }

        Integer difference = 0;

        for (Integer i = 0; i < this.values.size(); i++) {
            difference |= this.values[i] ^ other.values[i];
        }

        return difference == 0;
    }

    /**
     * @description Value equality, so that byte strings can be compared with `==` and used as
     * map keys. Not constant time: use `equalsConstantTime` for attacker-controlled input.
     * @param other The object to compare with.
     * @return true when other is a byte string with the same octets.
     */
    public Boolean equals(Object other) {
        if (!(other instanceof JweBytes)) {
            return false;
        }

        return this.values.equals(((JweBytes) other).values);
    }

    /**
     * @description Hash code consistent with `equals`.
     * @return The hash code.
     */
    public Integer hashCode() {
        return this.toHex().hashCode();
    }

    /**
     * @description Converts to the blob format required by `Crypto` and `EncodingUtil`.
     * @return The octets as a blob.
     */
    public Blob toBlob() {
        return EncodingUtil.convertFromHex(this.toHex());
    }

    /**
     * @description Converts to lower case hex, two digits per octet. It is the readable form
     * used by the RFC test vectors and the only form accepted back by `ofHex`.
     * @return The hex representation.
     */
    public String toHex() {
        List<Integer> digits = new List<Integer>(this.values.size() * 2);
        Integer next = 0;

        for (Integer value : this.values) {
            digits[next++] = HEX_DIGITS.charAt((value >>> BITS_PER_NIBBLE) & NIBBLE_MASK);
            digits[next++] = HEX_DIGITS.charAt(value & NIBBLE_MASK);
        }

        return digits.isEmpty() ? '' : String.fromCharArray(digits);
    }

    private void requireBounds(Integer fromIndex, Integer toIndex) {
        if (fromIndex == null || toIndex == null) {
            throw new JweException('Slice bounds cannot be null');
        }

        if (fromIndex < 0 || toIndex > this.values.size()) {
            throw new JweException(
                'Slice [' + fromIndex + ', ' + toIndex + ') is outside a ' + size() + ' byte string'
            );
        }

        if (toIndex < fromIndex) {
            throw new JweException('Slice end is before its start');
        }
    }

    private static Integer nibbleAt(String hex, Integer index) {
        Integer digit = HEX_DIGITS.indexOfChar(hex.charAt(index));

        if (digit == -1) {
            throw new JweException('Hex source has a character outside the hex alphabet');
        }

        return digit;
    }

    private static void requireLength(Integer length) {
        if (length == null || length < 0) {
            throw new JweException('Byte length must be a non-negative integer');
        }
    }
}
