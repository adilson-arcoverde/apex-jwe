/**
 * @description The JWE protected header: the first part of a compact token, and at the same
 * time the additional authenticated data of the content encryption. It carries which
 * algorithms produced the token (`alg`, `enc`) and, optionally, which key was used (`kid`).
 *
 * Two properties matter more than they look. The serialization is canonical, always `alg`,
 * `enc` and then `kid`, because the encoded header is authenticated as a string of octets:
 * whoever produces the token must produce exactly the octets it authenticates. And the values
 * are written through a JSON generator rather than a template, so a `kid` carrying a quote
 * cannot inject a second `alg` member into the header.
 *
 * On the receiving side the encoded header must be authenticated as received, never
 * re-serialized from a parsed instance: a header that reorders its members, adds whitespace or
 * carries a member this class ignores is a different string of octets, and it is the string
 * that was signed.
 *
 * Instances are immutable.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
 */
public inherited sharing class JweHeader {
    private static final String ALG_MEMBER = 'alg';
    private static final String ENC_MEMBER = 'enc';
    private static final String KID_MEMBER = 'kid';
    private static final String CRIT_MEMBER = 'crit';
    private static final String ZIP_MEMBER = 'zip';

    private final String algorithm;
    private final String encryption;
    private final String keyIdentifier;

    /**
     * @description Creates a header for a pair of algorithms.
     * @param alg The key management algorithm: 'dir', 'RSA-OAEP' or 'RSA-OAEP-256'.
     * @param enc The content encryption algorithm: 'A128CBC-HS256', 'A192CBC-HS384' or
     * 'A256CBC-HS512'.
     * @throws JweException When either value is blank. Which values are supported is decided
     * where the algorithms are built, not here.
     */
    public JweHeader(String alg, String enc) {
        this(alg, enc, null);
    }

    private JweHeader(String alg, String enc, String keyId) {
        if (String.isBlank(alg)) {
            throw new JweException('The header member alg cannot be blank');
        }

        if (String.isBlank(enc)) {
            throw new JweException('The header member enc cannot be blank');
        }

        this.algorithm = alg;
        this.encryption = enc;
        this.keyIdentifier = keyId;
    }

    /**
     * @description Returns a copy of this header that names the key it was built for, which is
     * how a recipient with more than one key knows which one to reach for.
     * @param keyId The key identifier, or null to omit the member.
     * @return A new header; this one is unchanged.
     */
    public JweHeader withKeyId(String keyId) {
        return new JweHeader(this.algorithm, this.encryption, keyId);
    }

    /**
     * @description The key management algorithm.
     * @return The `alg` value.
     */
    public String alg() {
        return this.algorithm;
    }

    /**
     * @description The content encryption algorithm.
     * @return The `enc` value.
     */
    public String enc() {
        return this.encryption;
    }

    /**
     * @description The key identifier.
     * @return The `kid` value, or null when the header carries none.
     */
    public String keyId() {
        return this.keyIdentifier;
    }

    /**
     * @description Whether another header names the same pair of algorithms. The comparison is
     * case sensitive, as RFC 7515 §4.1.1 requires of header values, and it ignores `kid`: the
     * key identifier says which key, not which algorithm.
     *
     * This is the anti-downgrade check. A recipient decides the algorithms it accepts in
     * advance and compares them with what the token claims, instead of letting the token
     * choose.
     * @param other The header to compare with, typically the one parsed from a token.
     * @return true when both `alg` and `enc` are identical.
     * @see https://www.rfc-editor.org/rfc/rfc7516#section-11.5
     */
    public Boolean hasSameAlgorithms(JweHeader other) {
        return other != null &&
            this.algorithm.equals(other.algorithm) &&
            this.encryption.equals(other.encryption);
    }

    /**
     * @description The canonical JSON of this header.
     * @return The JSON object as text.
     */
    public String toJson() {
        JSONGenerator generator = JSON.createGenerator(false);
        generator.writeStartObject();
        generator.writeStringField(ALG_MEMBER, this.algorithm);
        generator.writeStringField(ENC_MEMBER, this.encryption);

        if (this.keyIdentifier != null) {
            generator.writeStringField(KID_MEMBER, this.keyIdentifier);
        }

        generator.writeEndObject();

        return generator.getAsString();
    }

    /**
     * @description The header as it travels in a token: the canonical JSON, base64url encoded.
     * The same string is the additional authenticated data of the content encryption.
     * @return The encoded header.
     * @see https://www.rfc-editor.org/rfc/rfc7516#section-5.1
     */
    public String encode() {
        return JweBase64Url.encode(Blob.valueOf(this.toJson()));
    }

    /**
     * @description Reads the header of a received token.
     *
     * A token asking for something this library does not do is rejected rather than partly
     * honored: `zip` because a plaintext this library did not inflate is not the plaintext, and
     * `crit` because it exists precisely to say that ignoring a member is not acceptable.
     *
     * Failures carry specific messages. Everything that depends on a received token is
     * expected to surface through the uniform failure of the caller, which is what keeps a
     * decryption attempt from reporting which step it failed at.
     * @param encodedHeader The first part of a compact token, base64url encoded.
     * @return The parsed header.
     * @throws JweException When the part is not base64url, not a JSON object, missing `alg` or
     * `enc`, or asks for an extension this library does not implement.
     * @see https://www.rfc-editor.org/rfc/rfc7516#section-5.2
     */
    public static JweHeader parse(String encodedHeader) {
        String text = JweBase64Url.decodeToText(encodedHeader);

        Map<String, Object> members;

        try {
            members = (Map<String, Object>) JSON.deserializeUntyped(text);
        } catch (Exception e) {
            throw new JweException('The header is not a JSON object');
        }

        if (members.containsKey(CRIT_MEMBER)) {
            throw new JweException(
                'The header requires extensions this library does not implement'
            );
        }

        if (members.containsKey(ZIP_MEMBER)) {
            throw new JweException('Compressed payloads are not supported');
        }

        return new JweHeader(
            textMember(members, ALG_MEMBER),
            textMember(members, ENC_MEMBER),
            textMember(members, KID_MEMBER)
        );
    }

    private static String textMember(Map<String, Object> members, String name) {
        Object value = members.get(name);

        if (value == null) {
            return null;
        }

        if (!(value instanceof String)) {
            throw new JweException('The header member ' + name + ' must be a string');
        }

        return (String) value;
    }
}
