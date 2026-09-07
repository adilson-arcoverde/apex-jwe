/**
 * @description Tokens produced outside Apex, by jose 6.2.3 on Node, with the throwaway key of
 * JweTestKeys and the pre-shared key below. They are the behavior freeze of the wire
 * format: every one of them must keep decrypting to the same payload, before and after the
 * refactoring, with the baseline implementation and with the new one.
 *
 * Regenerate with scripts/generate-interop-vectors.mjs only when the wire format is meant to
 * change, which is to say almost never. Documented in docs/TEST-VECTORS.md.
 */
@IsTest
public class JweTestTokens {
    /** @description Pre-shared key for `dir` mode: MAC key followed by encryption key, hex. 64 octets for
     * A256CBC-HS512; its first 32 octets are the A128CBC-HS256 key. */
    public static final String AES_SHARED_KEY = 'ABF71E6E95AD9B75EF5D44F0BA4CEB94FBADF9FD2DBC3F460C73A7E58D0BA984ECC904EC1DE279E2737EDC93D688879ABFF4DCB6AFEC3A6E9E8217FB17C0394C';

    /** @description RSA-OAEP-256 with A256CBC-HS512. */
    public static final String RSA_OAEP_256_A256CBC_HS512_TOKEN = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiaW50ZXJvcC0zIn0.N4ZZ-bJ94A9HjiUAxC_27NaOazaN9goPxx6navKomaubMAoAm5ZIPmkwea_EeXKX8Ch2RNz68Gmk4m0WH_vUwG-ThA6UCHFjRfGQQmzzLyD2tD9JyU3ER_1RsLAgAvcmRVsS15QzDOvaHg1wm6KMsdt2QRhhcd0Fl_RsHQfqCtb1tb4wTfcv74n6d88ybaJuExKbffET1RVOnx8iKOVF8tUsIEXRVRdTbc7q3vCB5Y4yoDZniyfgKWJScapsDemFrrh7NXDOOOowl_wxZVXVSsACEo6Nj6ioRfcUNDp2SY7inH-d5BMBot4i-oNXdNQCfU8m-5KgW-5FJvu1tW-T0A.Ybju9HUSsgaQxoO1b_-Ebg.0GAQHHLAPNYw1Hyn0HQLrzwpY9QIALveTE5Ql9zLHQoMVlkUi4caWVbY1VnohLuB.KdbPeGdxPj6txzf2vCwToOip5O5hZ8mc6p_dsL0k6Xk';

    /** @description The payload of the RSA-OAEP-256 with A256CBC-HS512 token. */
    public static final String RSA_OAEP_256_A256CBC_HS512_PAYLOAD = 'RSA-OAEP-256 interop reference payload';

    /** @description RSA-OAEP (SHA-1) with A128CBC-HS256. */
    public static final String RSA_OAEP_A128CBC_HS256_TOKEN = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiJpbnRlcm9wLTQifQ.cJAUq7C6qu9BX5LvjdVmqp8LnwGyddgOrYyBQGzrFQB-iWhJ4F9Y32GSgCKq-EF-1Zsu30QcRyCy7s6YGDjtjZGegkKcbFHSS8ZPB9GHe6Wix8a2W8wD1NHngaZgM0bSn2g_4dpFv2ALvdd0gaMto1q9I4XE8YbaGQFwJLGq9ny4PlS6nLNf6tAz42KL9zl5ARYViMuF9Sa_5UCnVKSVfdE-CWKxv56dS_a5pO2GDt-N_sXQVOzNIyjPbeTy2h_D90Rcyr4xuh7VtL4bfrV6D-OuPG4S27S3cb1DY0ZtQQizPOsC8DTgPsI9A3YxW5IeRXtJXc8QgTFzNdU6NQ7rkA.CxCghV13bHO7BTRl2H0GRQ.3hhK2_B0k3pnGeL5xhweNFFdGqF6TpkAMr-G3GJm4ssV2ADdf6mHe71AD76pDSnv.-zuLmTXNie2pKpe72nUGWA';

    /** @description The payload of the RSA-OAEP with A128CBC-HS256 token. */
    public static final String RSA_OAEP_A128CBC_HS256_PAYLOAD = 'RSA-OAEP A128 interop reference payload';

    /** @description Direct encryption with A128CBC-HS256. */
    public static final String DIR_A128CBC_HS256_TOKEN = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiaW50ZXJvcC01In0..xPLPYX_XhfeObb3YpMahEg.suG4uRR9FDXrvBD0DPzqd7u22piqk3mVq2DQEd4iCHM4thBIfpD-aqSGbM4WFxyt.fe2Xene2gq1XcuKdseH96A';

    /** @description The payload of the `dir` token, which ends in characters that differ between the
     * standard and the URL-safe base64 alphabets. */
    public static final String DIR_A128CBC_HS256_PAYLOAD = 'dir A128 interop reference payload +/=';

    /** @description RSA-OAEP-256 with A128CBC-HS256, the mixed pair. */
    public static final String RSA_OAEP_256_A128CBC_HS256_TOKEN = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiaW50ZXJvcC02In0.KgQvc4r2_qqVbaxWngUcXMIx2RzDU7YbJ-R189N0Ai_CGTVqJBljdC0wS6V_f8EEVbHWPZP9G45iFwTfU4bw9x4vjLpILvKxe42mC-qOIKrWIfdnW74dRs2UF9EAGz3tPz28VeAAfTegKIW5ZW-bsSwJtkHUVodlrVbPZ2oZ6KBmxBcFjaTPdcyto1Jp7AluFibVIv7MqaOGMn7GYYpcme0HN_muMNaDBOCSGmBkINCLXzSUul96lZs2oV7B6-lgn63fqxQB0mCvI3_ee9pRug77V9M_Q2WGdkV-gd3_GAtZNEJw1Sau5vBYO9-xkiYtBsej6AGAWiMxPPUNZzX6Sg.JZ4bD7dtd5jPGh7jvlHQjw.LZuHzc0XZUhjctdSdW0J82WTfLT2xJHhZPj3A-GHSevcN8_9AFC9eBkf3t3PAaIm.NIKBQl94GxBYujUcEih7NQ';

    /** @description The payload of the RSA-OAEP-256 with A128CBC-HS256 token. */
    public static final String RSA_OAEP_256_A128CBC_HS256_PAYLOAD = 'OAEP-256 with A128 interop payload';

    /**
     * @description Direct encryption with A256CBC-HS512. Produced earlier than the tokens
     * above, with the Node `crypto` module rather than jose, which is why it is kept: two
     * independent producers of the same wire format.
     */
    public static final String DIR_A256CBC_HS512_TOKEN = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiaW50ZXJvcC0xIn0..AAECAwQFBgcICQoLDA0ODw.URcE4TdfBVYY0ZrarStfz8AvFQ4GupOWedVWByjJJkE.DWF7yccc1ELRXEdMt4It2R4pYvZGC45xM6ka0IZsyfE';

    /** @description The payload of the `dir` with A256CBC-HS512 token. */
    public static final String DIR_A256CBC_HS512_PAYLOAD = 'Interop reference payload +/=';

    /** @description RSA-OAEP (SHA-1) with A256CBC-HS512, also produced with Node `crypto`. */
    public static final String RSA_OAEP_A256CBC_HS512_TOKEN = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJraWQiOiJpbnRlcm9wLTIifQ.ovuFi6yc-acnjOSxlMtyKZjTAeRagravWWXP5JoeJYQ3-feeyDnJkxM79mi1vLOYknuCKcRSwA_rs6YG9pTkwh5A9_hKEzFKvKDld2yvzfbA4bG3iSJN_q-Qui4s_e9XR7VQV3dl79V5q0nkEafSy4TzR1kkwjW-OjU9Sh_Z-yv2YVFRiqOkH1ia7kwOeSLEgEWKvLZkltSSvKuWWaGzoUEPgrLYqAuzwzOmGKw0SS8yJr-Y2HxdGyC6zHVN7MGeulDFahdIvmOhA7dXKYuDl1ZWAHySWDAy5RkY4OXIRw4FDl1YpnaZcI-iJRYmZcnlggZ8KGf1jWpVyunr4ylgBg.8PHy8_T19vf4-fr7_P3-_w.HOVW8MO8M9aikQily0UL3E7gLKSK2cJTNuy5Ir3CYbU.y1r-pj1fQPfS2HkdL5SHvkxwT_NLMaUsO5LZ_tK3va4';

    /** @description The payload of the RSA-OAEP with A256CBC-HS512 token. */
    public static final String RSA_OAEP_A256CBC_HS512_PAYLOAD = 'RSA interop reference payload';

    /**
     * @description A shared key that decrypts none of these tokens, for asserting that the
     * wrong key fails like anything else wrong with a token. 32 octets, so it is a valid
     * A128CBC-HS256 key.
     */
    public static final String WRONG_SHARED_KEY = 'D9C81818C4C0E956AC2B865F2030BA1813460691A6E62E645864DCCD72E67390';
}
