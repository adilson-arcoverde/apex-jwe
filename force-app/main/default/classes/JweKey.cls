/**
 * @description A key in JWK form (RFC 7517), which is how JOSE keys are published and
 * exchanged. Two kinds are supported, because JWE uses two:
 *
 * - `kty` **RSA**, for the `RSA-OAEP` and `RSA-OAEP-256` key management algorithms. `n` and `e`
 *   are required, as RFC 7518 §6.3.1 requires them of any RSA key, public or private. The
 *   private members are optional: a key carrying only `n` and `e` can wrap a content
 *   encryption key but not unwrap one.
 * - `kty` **oct**, for `dir`, where there is no key management at all and the octets of `k`
 *   are themselves the content encryption key.
 *
 * Members the library does not use (`alg`, `use`, `kid`, `key_ops`) are accepted and ignored,
 * so a key published for a wider purpose still parses.
 *
 * Where the key comes from is the caller's business: this class reads JSON and hex, and has no
 * opinion on whether that JSON arrived from protected custom metadata, a named credential, a
 * callout to a key service or a test constant.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-6
 */
public inherited sharing class JweKey {
    private static final String RSA_KEY_TYPE = 'RSA';
    private static final String SYMMETRIC_KEY_TYPE = 'oct';
    private static final String KEY_TYPE = 'kty';
    private static final String MODULUS = 'n';
    private static final String PUBLIC_EXPONENT = 'e';
    private static final String PRIVATE_EXPONENT = 'd';
    private static final String SECRET_MEMBER = 'k';

    /** @description The RSA members read from a JWK, in the order of RFC 7518 §6.3. */
    private static final List<String> RSA_MEMBERS = new List<String>{
        'n',
        'e',
        'd',
        'p',
        'q',
        'dp',
        'dq',
        'qi'
    };

    /** @description The five members that together allow the CRT decryption path. */
    private static final List<String> CRT_MEMBERS = new List<String>{ 'p', 'q', 'dp', 'dq', 'qi' };

    private final String keyType;
    private final Map<String, String> members;
    private final Blob modulusOctetString;

    private JweKey(String keyType, Map<String, String> members) {
        this.keyType = keyType;
        this.members = members;
        this.modulusOctetString = RSA_KEY_TYPE.equals(keyType)
            ? JweBase64Url.decode(members.get(MODULUS))
            : null;
    }

    /**
     * @description Parses a JWK.
     * @param keyJson The key as a JSON object.
     * @return The parsed key.
     * @throws JweException When the JSON is not an object, the key type is neither RSA nor
     * oct, a required member is missing, or a member is not a base64url string.
     */
    public static JweKey fromJson(String keyJson) {
        if (String.isBlank(keyJson)) {
            throw new JweException('Key JSON cannot be blank');
        }

        Map<String, Object> raw;

        try {
            raw = (Map<String, Object>) JSON.deserializeUntyped(keyJson);
        } catch (Exception e) {
            throw new JweException('Key JSON is not a JSON object');
        }

        String keyType = textMember(raw, KEY_TYPE);

        if (SYMMETRIC_KEY_TYPE.equals(keyType)) {
            return symmetric(textMember(raw, SECRET_MEMBER));
        }

        if (!RSA_KEY_TYPE.equals(keyType)) {
            throw new JweException(
                'Only RSA and oct keys are supported, and this one is: ' + keyType
            );
        }

        Map<String, String> members = readMembers(raw);

        if (!members.containsKey(MODULUS) || !members.containsKey(PUBLIC_EXPONENT)) {
            throw new JweException('An RSA key requires the members n and e');
        }

        return new JweKey(RSA_KEY_TYPE, members);
    }

    /**
     * @description Builds a symmetric key from its octets in hex, for the `dir` algorithm.
     * It is the same key a JWK with `kty` oct carries in `k`, in the form a pre-shared secret
     * is usually configured.
     * @param secretHex The key octets as hex: MAC key followed by encryption key, 32 octets
     * for A128CBC-HS256 and 64 for A256CBC-HS512.
     * @return The key.
     * @throws JweException When the hex is null, of odd length, or not hex.
     */
    public static JweKey fromSecretHex(String secretHex) {
        if (secretHex == null) {
            throw new JweException('The shared key cannot be null');
        }

        return symmetric(JweBase64Url.encode(JweBytes.ofHex(secretHex).toBlob()));
    }

    /**
     * @description Whether this is a symmetric key, that is, a `kty` oct key whose octets are
     * the content encryption key itself.
     * @return true for an oct key, false for an RSA key.
     */
    public Boolean isSymmetric() {
        return SYMMETRIC_KEY_TYPE.equals(this.keyType);
    }

    /**
     * @description The octets of a symmetric key.
     * @return The key material.
     * @throws JweException When this is an RSA key.
     */
    public Blob secret() {
        requireSymmetric(true, 'shared key octets');

        return JweBase64Url.decode(this.members.get(SECRET_MEMBER));
    }

    /**
     * @description The length of the modulus in octets, `k` in RFC 8017. It is the length of
     * every RSA ciphertext this key produces or accepts, and it comes from the encoded length
     * of `n` rather than from its value, so a modulus with a leading zero octet keeps its
     * declared size.
     * @return The modulus length in octets.
     * @throws JweException When this is a symmetric key.
     */
    public Integer modulusOctets() {
        requireSymmetric(false, 'modulus');

        return this.modulusOctetString.size();
    }

    /**
     * @description The modulus n.
     * @return The modulus.
     * @throws JweException When this is a symmetric key.
     */
    public JweBigInt modulus() {
        requireSymmetric(false, 'modulus');

        return JweBigInt.fromBytes(this.modulusOctetString);
    }

    /**
     * @description The public exponent e.
     * @return The public exponent.
     * @throws JweException When this is a symmetric key.
     */
    public JweBigInt publicExponent() {
        requireSymmetric(false, 'public exponent');

        return integerMember(PUBLIC_EXPONENT);
    }

    /**
     * @description The private exponent d.
     * @return The private exponent.
     * @throws JweException When the key carries no private exponent.
     */
    public JweBigInt privateExponent() {
        if (!hasPrivateExponent()) {
            throw new JweException('The key carries no private exponent d');
        }

        return integerMember(PRIVATE_EXPONENT);
    }

    /**
     * @description Whether this key can decrypt, that is, whether it carries d.
     * @return true when the private exponent is present.
     */
    public Boolean hasPrivateExponent() {
        return this.members.containsKey(PRIVATE_EXPONENT);
    }

    /**
     * @description Whether this key carries the five CRT members, which is what makes the fast
     * decryption path available.
     * @return true when p, q, dp, dq and qi are all present.
     */
    public Boolean hasCrtParameters() {
        for (String name : CRT_MEMBERS) {
            if (!this.members.containsKey(name)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @description The CRT members as integers.
     * @return The CRT parameters.
     * @throws JweException When any of the five members is missing.
     */
    public JweBigInt.CrtParameters crtParameters() {
        if (!hasCrtParameters()) {
            throw new JweException('The key carries no CRT members p, q, dp, dq and qi');
        }

        JweBigInt.CrtParameters crt = new JweBigInt.CrtParameters();
        crt.p = integerMember('p');
        crt.q = integerMember('q');
        crt.dp = integerMember('dp');
        crt.dq = integerMember('dq');
        crt.qi = integerMember('qi');

        return crt;
    }

    private static JweKey symmetric(String secret) {
        if (String.isBlank(secret)) {
            throw new JweException('An oct key requires the member k');
        }

        // Decoded here so that a key that is not base64url fails while it is being built,
        // rather than in the middle of an encryption.
        JweBase64Url.decode(secret);

        return new JweKey(SYMMETRIC_KEY_TYPE, new Map<String, String>{ SECRET_MEMBER => secret });
    }

    private void requireSymmetric(Boolean expected, String wanted) {
        if (isSymmetric() == expected) {
            return;
        }

        throw new JweException(
            'This is ' +
                (isSymmetric() ? 'a symmetric key' : 'an RSA key') +
                ', so it has no ' +
                wanted
        );
    }

    private JweBigInt integerMember(String name) {
        return JweBigInt.fromBytes(JweBase64Url.decode(this.members.get(name)));
    }

    /**
     * @description Collects the RSA members that are present, ignoring everything else the JWK
     * carries.
     * @param raw The parsed JSON object.
     * @return The members by name, base64url encoded.
     * @throws JweException When a member is present but is not a string.
     */
    private static Map<String, String> readMembers(Map<String, Object> raw) {
        Map<String, String> members = new Map<String, String>();

        for (String name : RSA_MEMBERS) {
            String value = textMember(raw, name);

            if (String.isNotBlank(value)) {
                members.put(name, value);
            }
        }

        return members;
    }

    private static String textMember(Map<String, Object> raw, String name) {
        Object value = raw.get(name);

        if (value == null) {
            return null;
        }

        if (!(value instanceof String)) {
            throw new JweException('Key member ' + name + ' must be a string');
        }

        return (String) value;
    }
}
