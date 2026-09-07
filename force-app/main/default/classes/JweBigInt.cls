/**
 * @description Non-negative big integer arithmetic for RSA, built on `Decimal`.
 *
 * Apex has no big integer type and no integer wide enough for an RSA modulus. `Decimal` is
 * arbitrary precision, and restricted to whole numbers it provides exactly the three
 * operations RSAES-OAEP needs: modular reduction, modular exponentiation and the Chinese
 * Remainder Theorem recombination. This is the whole arithmetic layer of the library, kept
 * apart from the padding scheme so that it can be verified against plain number theory
 * vectors instead of only through OAEP round trips.
 *
 * Values are immutable and never negative.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8017#section-5.1
 */
public inherited sharing class JweBigInt {
    private static final String HEX_DIGITS = '0123456789abcdef';
    private static final Decimal HEX_BASE = 16;
    private static final Integer HEX_DIGITS_PER_OCTET = 2;

    private final Decimal value;

    private JweBigInt(Decimal value) {
        this.value = value;
    }

    /**
     * @description Reads an integer from its hex representation, the format in which RSA key
     * parameters and test vectors are published.
     * @param hex The hex digits, upper or lower case. An empty string reads as zero.
     * @return The integer.
     * @throws JweException When hex is null or carries a character outside the hex alphabet.
     */
    public static JweBigInt fromHex(String hex) {
        if (hex == null) {
            throw new JweException('Hex source cannot be null');
        }

        // Horner form: one multiplication and one addition per digit, so the cost is linear
        // in the size of the key parameter instead of quadratic.
        Decimal result = 0;
        String normalized = hex.toLowerCase();

        for (Integer i = 0; i < normalized.length(); i++) {
            Integer digit = HEX_DIGITS.indexOfChar(normalized.charAt(i));

            if (digit == -1) {
                throw new JweException('Hex source has a character outside the hex alphabet');
            }

            result = result * HEX_BASE + digit;
        }

        return new JweBigInt(result);
    }

    /**
     * @description OS2IP: reads an octet string as a big-endian non-negative integer.
     * @param data The octets to read.
     * @return The integer.
     * @throws JweException When data is null.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-4.2
     */
    public static JweBigInt fromBytes(Blob data) {
        if (data == null) {
            throw new JweException('Byte source cannot be null');
        }

        return fromHex(EncodingUtil.convertToHex(data));
    }

    /**
     * @description Wraps a small integer, for exponents and test vectors.
     * @param value The non-negative value to wrap.
     * @return The integer.
     * @throws JweException When value is null or negative.
     */
    public static JweBigInt valueOf(Long value) {
        if (value == null || value < 0) {
            throw new JweException('Big integer value must be non-negative');
        }

        return new JweBigInt(Decimal.valueOf(value));
    }

    /**
     * @description Reduces this integer modulo another one.
     * @param modulus The modulus. Must be positive.
     * @return The remainder, in the range 0 to modulus - 1.
     * @throws JweException When modulus is null or not positive.
     */
    public JweBigInt mod(JweBigInt modulus) {
        requirePositive(modulus);

        return new JweBigInt(modulo(this.value, modulus.value));
    }

    /**
     * @description Whether this integer is smaller than another one. RSA decryption needs the
     * comparison to reject a ciphertext representative outside the range 0 to n - 1 before
     * touching the private key.
     * @param other The integer to compare with.
     * @return true when this integer is smaller than other.
     * @throws JweException When other is null.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-7.1.2
     */
    public Boolean isLessThan(JweBigInt other) {
        if (other == null) {
            throw new JweException('Comparison operand cannot be null');
        }

        return this.value < other.value;
    }

    /**
     * @description Modular exponentiation by square and multiply, the RSAEP and RSADP
     * primitive: `this^exponent mod modulus`.
     * @param exponent The exponent. Zero yields one.
     * @param modulus The modulus. Must be positive.
     * @return The result of the exponentiation.
     * @throws JweException When exponent or modulus is null, or modulus is not positive.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-5.1.1
     */
    public JweBigInt modPow(JweBigInt exponent, JweBigInt modulus) {
        if (exponent == null) {
            throw new JweException('Exponent cannot be null');
        }

        requirePositive(modulus);

        Decimal m = modulus.value;
        Decimal base = modulo(this.value, m);
        Decimal exp = exponent.value;
        Decimal result = 1;

        while (exp > 0) {
            // Parity comes from the low-order 64 bits: `longValue()` truncates a wider
            // Decimal, and truncation cannot change the last bit.
            if ((exp.longValue() & 1) == 1) {
                result = modulo(result * base, m);
            }

            base = modulo(base * base, m);
            exp = exp.divide(2, 0, RoundingMode.FLOOR);
        }

        return new JweBigInt(result);
    }

    /**
     * @description Modular exponentiation with the private exponent, through the Chinese
     * Remainder Theorem. Two exponentiations of half the size replace one of full size, which
     * is what makes an RSA-2048 decryption fit in the Apex CPU limit.
     * @param crt The CRT parameters of the private key.
     * @return `this^d mod n`, computed from the factors of n.
     * @throws JweException When any CRT parameter is missing.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-5.1.2
     */
    public JweBigInt modPowCrt(CrtParameters crt) {
        if (crt == null) {
            throw new JweException('CRT parameters cannot be null');
        }

        crt.validate();

        JweBigInt m1 = this.mod(crt.p).modPow(crt.dp, crt.p);
        JweBigInt m2 = this.mod(crt.q).modPow(crt.dq, crt.q);

        // h = qi * (m1 - m2) mod p. The difference can be negative; floor division gives a
        // remainder with the sign of the divisor, so the result is already in range.
        Decimal h = modulo(crt.qi.value * modulo(m1.value - m2.value, crt.p.value), crt.p.value);

        return new JweBigInt(m2.value + h * crt.q.value);
    }

    /**
     * @description Converts to lower case hex, with an even number of digits and no leading
     * zero octet. Zero converts to `00`.
     * @return The hex representation.
     */
    public String toHex() {
        String digits = rawHex();

        if (String.isEmpty(digits)) {
            return '00';
        }

        return Math.mod(digits.length(), HEX_DIGITS_PER_OCTET) == 0 ? digits : '0' + digits;
    }

    /**
     * @description I2OSP: converts to hex of a fixed octet length, left padded with zeros.
     * RSA requires the ciphertext and the encoded message to be exactly as long as the
     * modulus, so the padding here is part of the wire format, not cosmetic.
     * @param octets The exact number of octets of the result.
     * @return The hex representation, `2 * octets` digits long.
     * @throws JweException When octets is null or negative, or the integer does not fit.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-4.1
     */
    public String toHex(Integer octets) {
        if (octets == null || octets < 0) {
            throw new JweException('Octet length must be a non-negative integer');
        }

        String digits = rawHex();
        Integer width = octets * HEX_DIGITS_PER_OCTET;

        if (digits.length() > width) {
            throw new JweException('Integer is too large for ' + octets + ' octets');
        }

        return digits.leftPad(width, '0');
    }

    /**
     * @description I2OSP: converts to an octet string of a fixed length.
     * @param octets The exact number of octets of the result.
     * @return The integer as octets, most significant first.
     * @throws JweException When octets is null or negative, or the integer does not fit.
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-4.1
     */
    public Blob toBlob(Integer octets) {
        return EncodingUtil.convertFromHex(this.toHex(octets));
    }

    /**
     * @description Value equality, so that integers can be compared with `==`.
     * @param other The object to compare with.
     * @return true when other is an integer of the same value.
     */
    public Boolean equals(Object other) {
        if (!(other instanceof JweBigInt)) {
            return false;
        }

        return this.value == ((JweBigInt) other).value;
    }

    /**
     * @description Hash code consistent with `equals`.
     * @return The hash code.
     */
    public Integer hashCode() {
        return this.toHex().hashCode();
    }

    /**
     * @description The hex digits of this integer, least significant last, with no padding.
     *
     * The digits fall out of the division least significant first, and are collected as
     * character codes and reversed at the end. Prepending each one to a growing String would
     * copy the whole String every time, which for a 2048 bit value means 512 copies.
     * @return The hex digits, or an empty string for zero.
     */
    private String rawHex() {
        List<Integer> digits = new List<Integer>();
        Decimal remaining = this.value;

        while (remaining > 0) {
            digits.add(HEX_DIGITS.charAt(modulo(remaining, HEX_BASE).intValue()));
            remaining = remaining.divide(HEX_BASE, 0, RoundingMode.FLOOR);
        }

        if (digits.isEmpty()) {
            return '';
        }

        List<Integer> ordered = new List<Integer>(digits.size());

        for (Integer i = 0; i < digits.size(); i++) {
            ordered[digits.size() - 1 - i] = digits[i];
        }

        return String.fromCharArray(ordered);
    }

    private static void requirePositive(JweBigInt modulus) {
        if (modulus == null) {
            throw new JweException('Modulus cannot be null');
        }

        if (modulus.value < 1) {
            throw new JweException('Modulus must be positive');
        }
    }

    /**
     * @description Floor modulo. Apex has no modulo operator for `Decimal`, and floor
     * division is what makes the remainder of a negative dividend land in the range of the
     * divisor, as the CRT recombination requires.
     * @param dividend The dividend.
     * @param divisor The divisor.
     * @return The remainder.
     */
    private static Decimal modulo(Decimal dividend, Decimal divisor) {
        Decimal quotient = dividend.divide(divisor, 0, RoundingMode.FLOOR);

        return dividend - quotient * divisor;
    }

    /**
     * @description The five CRT parameters of an RSA private key, as published in a JWK.
     * Grouped in one type because they are only meaningful together.
     * @see https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2
     */
    public class CrtParameters {
        /** @description The first prime factor of the modulus. */
        public JweBigInt p;
        /** @description The second prime factor of the modulus. */
        public JweBigInt q;
        /** @description The private exponent modulo p - 1. */
        public JweBigInt dp;
        /** @description The private exponent modulo q - 1. */
        public JweBigInt dq;
        /** @description The inverse of q modulo p. */
        public JweBigInt qi;

        private void validate() {
            if (p == null || q == null || dp == null || dq == null || qi == null) {
                throw new JweException('CRT parameters p, q, dp, dq and qi are all required');
            }
        }
    }
}
