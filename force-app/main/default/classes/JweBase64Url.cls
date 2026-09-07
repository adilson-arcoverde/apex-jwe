/**
 * @description Base64URL encoding without padding, the only encoding used by the JWE Compact
 * Serialization: the five parts of a token, and the components of an RSA JWK, are all
 * base64url strings.
 *
 * The platform provides Base64 with the standard alphabet, so the two differing characters
 * are translated and the padding is stripped on the way out and restored on the way in.
 * Decoding is strict: anything outside the URL and filename safe alphabet is rejected instead
 * of being ignored, because a token that decodes under a lenient parser but not under a strict
 * one is a token whose meaning depends on the implementation.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#appendix-C
 * @see https://www.rfc-editor.org/rfc/rfc4648#section-5
 */
public inherited sharing class JweBase64Url {
    private static final Pattern ALPHABET = Pattern.compile('[A-Za-z0-9_-]*');
    private static final Integer QUANTUM = 4;

    /**
     * @description Encodes octets as base64url, without padding.
     * @param data The octets to encode.
     * @return The encoded string.
     * @throws JweException When data is null.
     */
    public static String encode(Blob data) {
        if (data == null) {
            throw new JweException('Base64URL input cannot be null');
        }

        return EncodingUtil.base64Encode(data).replace('+', '-').replace('/', '_').remove('=');
    }

    /**
     * @description Decodes a base64url string into octets.
     * @param encoded The string to decode. Padding is neither required nor accepted.
     * @return The decoded octets.
     * @throws JweException When encoded is null, carries a character outside the base64url
     * alphabet, or has a length that no octet string can produce.
     */
    public static Blob decode(String encoded) {
        if (encoded == null) {
            throw new JweException('Base64URL input cannot be null');
        }

        if (!ALPHABET.matcher(encoded).matches()) {
            throw new JweException('Base64URL input has a character outside the alphabet');
        }

        Integer remainder = Math.mod(encoded.length(), QUANTUM);

        // A final quantum of a single character encodes no octet: it can only come from
        // truncation or from stripped padding of a longer string.
        if (remainder == 1) {
            throw new JweException('Base64URL input has an invalid length');
        }

        String standard = encoded.replace('-', '+').replace('_', '/');

        if (remainder > 0) {
            standard += '='.repeat(QUANTUM - remainder);
        }

        return EncodingUtil.base64Decode(standard);
    }

    /**
     * @description Decodes a base64url string into text, for the parts of a token that carry
     * UTF-8 rather than key material: the protected header and the plaintext.
     * @param encoded The string to decode.
     * @return The decoded text.
     * @throws JweException When encoded is not a valid base64url string.
     */
    public static String decodeToText(String encoded) {
        return decode(encoded).toString();
    }
}
