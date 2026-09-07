/**
 * @description Single exception type of the library.
 *
 * Two kinds of message travel through it, and the distinction is deliberate:
 * configuration and programming errors carry a specific message (wrong hash algorithm,
 * missing key parameter, byte length mismatch), while every failure that depends on the
 * content of a received token carries the same uniform message, so that a decryption
 * attempt reveals nothing about which step failed.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7516#section-11.5
 */
public class JweException extends Exception {
}
