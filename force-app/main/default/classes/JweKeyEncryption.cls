/**
 * @description A JWE key management algorithm: how the content encryption key reaches the
 * recipient. `JweRsaOaep` implements it for `RSA-OAEP` and `RSA-OAEP-256`.
 *
 * `dir` is deliberately not an implementation. In direct encryption there is nothing to wrap:
 * the recipient already holds the content encryption key and the encrypted key part of the
 * token is empty, so a `dir` implementation would be two methods that both refuse to work.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-4
 */
public interface JweKeyEncryption {
    /**
     * @description Encrypts a content encryption key for a recipient.
     * @param contentEncryptionKey The key to wrap.
     * @param key The recipient's key.
     * @return The wrapped key, to be carried as the second part of the token.
     */
    Blob wrap(Blob contentEncryptionKey, JweKey key);

    /**
     * @description Recovers a content encryption key addressed to the holder of the key.
     * @param wrappedKey The wrapped key from the token.
     * @param key The recipient's key, including its private members.
     * @return The content encryption key.
     */
    Blob unwrap(Blob wrappedKey, JweKey key);
}
