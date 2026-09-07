/**
 * @description Keys shared by the test classes of the library, kept in one place so that a
 * 2048 bit JWK is not pasted into every suite that needs one.
 *
 * Throwaway keys. They were generated for this repository, are published with it, and must
 * never be used to protect anything.
 */
@IsTest
public class JweTestKeys {
    /** @description Full private RSA-2048 JWK: n, e, d and the five CRT members. */
    public static final String RSA_PRIVATE_JWK = '{"kty":"RSA","n":"wD3pdCaSFdNajV-z1uU6wR-zbHTBg-17JJsxyjVxXhggOFYU6JJC6fMuri79leIEviMMsRUYH9qqX9LY2Dtcgafb-beYQ60PHRH8fTZS9894CKOLGEa-eAje7utAVaQrEWEnUFDIFdCbHAfQEzaB8wsj2d4-dF4OMc4R5An6ifqtWHsrJ8VWXfc_ywxTuuNzf_KcOpO3jTKXgB3_XI6oWujiHa_0LBBGJv9ngyCIb6ahU-baNhb2Fi5Ore1gSuTSL84m-1oj33LxWQdIqlsNTfSO54CqotWJmb6RWnjZiljB4PZMkJT0tzVY9ays05SNItoJMAzf5LErRMOm6zRVgQ","e":"AQAB","d":"qnb7yOvexA27EPtY2-g-FjvG_Rf29MYjWM1o9BY5pacdAveJ6MSxIwRpUzkF0d8uN2-a9HdxAeYDB59Oe0b_-1ReYetj0Dbn3O4zBtCh92330Sk70NYCVSwAirj-PjKpoeqVUsme8oEc2VkwL6k4x8wMCUfh94vjaFSDVsNmbuvZT_RdLcWvAxCc7CfY0cLbK5gIESSsRfMNa5-gC2Om9hiu0Y3An-Rg98ZuFiGxKuXr0LnhGw-q8QjBx2nDF71l-5c-gJa3P0QQQjOFbo_D1EM_hT5GIJ2Cn0k93CCSVGmBxt0qSDGXaqOo6WANyJK01TrCLYb8DUA1l9NVAKMoBQ","p":"4FXdAf3n6s42RbPREl8YrXQ9-ZPLTzMyt8L2JtAsZUT6c95vAjv00-Ta5T91AN8i68FxkkRL1EpWAO2OsuwZa8-NcaQf426g1TyHEDisBvKMdGZYiiBpe3gjKkHWkgtsZA7-ohNmJ5gVRord1mUloLEaqnKKoetFuovV9ZpDcM8","q":"22BhNtCPBqcJeTjD02Sc3OFe4pDgevKXFMmxUz4DFyCO7RJyHqFeU6wc06cMVA1BpmXQCtXvmSykVzaM6X6rIOkHdlVwJVKC80T7NzAvp78I2KGY_cL7Z3PE69LXGsPugI7b1U05ThQlrEYAqOw8MiFxPeuRpQG47JwmSqKgSK8","dp":"Talr-WSNBRyebULy_gkt4d58Fgq0N5bh1_wGeylWNTjL-5DlnUBkYXa40ORG_SZCUJuHVbuPBM83NtsGq6pQoqIXtV-8KmACDdAGcfcslrshJKrJvAe8fKH6ioaAYc7Sl1EZlcJhexOLSgCJC8-4Vwj40kkU9TkdypbeW0gsUME","dq":"U4squnNGZKQsKWwCt3hzfHKfbez6cBf-jT4aN7c_-gi-JW6G4z9U6sx61eeh_EhoHfRb_CRo8I5dr5DorOs-RHQ6EUiMQspfcEFu4h-JpnpL5iP0XX9puoYOEjjjDiBbrb253ktgbWmixy6JhcshSX4O4CPb_VjgkcsNkhLIs6U","qi":"gdeMs-8t647ueRbzg9UvVTwjjETELB-5E0iErPUdY_Ot_twuWQ0I5RbsFSMaGLLQE7xLhn09cmW3N86GSy3PW3D5TnpFCakQGGESYeaoOn28CGDkUurOcKZpAcDgUCauSd2jE1JathtjiUZ-SHzbxJtWylz2c9bmHyMxfYk7qYM"}';

    /** @description The same key with only the public members, so it cannot unwrap. */
    public static final String RSA_PUBLIC_JWK = '{"kty":"RSA","n":"wD3pdCaSFdNajV-z1uU6wR-zbHTBg-17JJsxyjVxXhggOFYU6JJC6fMuri79leIEviMMsRUYH9qqX9LY2Dtcgafb-beYQ60PHRH8fTZS9894CKOLGEa-eAje7utAVaQrEWEnUFDIFdCbHAfQEzaB8wsj2d4-dF4OMc4R5An6ifqtWHsrJ8VWXfc_ywxTuuNzf_KcOpO3jTKXgB3_XI6oWujiHa_0LBBGJv9ngyCIb6ahU-baNhb2Fi5Ore1gSuTSL84m-1oj33LxWQdIqlsNTfSO54CqotWJmb6RWnjZiljB4PZMkJT0tzVY9ays05SNItoJMAzf5LErRMOm6zRVgQ","e":"AQAB"}';

    /** @description The same key without the CRT members, which forces the slow d path. */
    public static final String RSA_PRIVATE_JWK_WITHOUT_CRT = '{"kty":"RSA","n":"wD3pdCaSFdNajV-z1uU6wR-zbHTBg-17JJsxyjVxXhggOFYU6JJC6fMuri79leIEviMMsRUYH9qqX9LY2Dtcgafb-beYQ60PHRH8fTZS9894CKOLGEa-eAje7utAVaQrEWEnUFDIFdCbHAfQEzaB8wsj2d4-dF4OMc4R5An6ifqtWHsrJ8VWXfc_ywxTuuNzf_KcOpO3jTKXgB3_XI6oWujiHa_0LBBGJv9ngyCIb6ahU-baNhb2Fi5Ore1gSuTSL84m-1oj33LxWQdIqlsNTfSO54CqotWJmb6RWnjZiljB4PZMkJT0tzVY9ays05SNItoJMAzf5LErRMOm6zRVgQ","e":"AQAB","d":"qnb7yOvexA27EPtY2-g-FjvG_Rf29MYjWM1o9BY5pacdAveJ6MSxIwRpUzkF0d8uN2-a9HdxAeYDB59Oe0b_-1ReYetj0Dbn3O4zBtCh92330Sk70NYCVSwAirj-PjKpoeqVUsme8oEc2VkwL6k4x8wMCUfh94vjaFSDVsNmbuvZT_RdLcWvAxCc7CfY0cLbK5gIESSsRfMNa5-gC2Om9hiu0Y3An-Rg98ZuFiGxKuXr0LnhGw-q8QjBx2nDF71l-5c-gJa3P0QQQjOFbo_D1EM_hT5GIJ2Cn0k93CCSVGmBxt0qSDGXaqOo6WANyJK01TrCLYb8DUA1l9NVAKMoBQ"}';

    /**
     * @description The full private key.
     * @return The parsed key.
     */
    public static JweKey rsaPrivateKey() {
        return JweKey.fromJson(RSA_PRIVATE_JWK);
    }

    /**
     * @description The public half of the key.
     * @return The parsed key.
     */
    public static JweKey rsaPublicKey() {
        return JweKey.fromJson(RSA_PUBLIC_JWK);
    }

    /**
     * @description The private key without its CRT members.
     * @return The parsed key.
     */
    public static JweKey rsaPrivateKeyWithoutCrt() {
        return JweKey.fromJson(RSA_PRIVATE_JWK_WITHOUT_CRT);
    }
}
