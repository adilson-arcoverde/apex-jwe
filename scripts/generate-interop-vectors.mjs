// Generates JWE interop tokens with the `jose` library (Node) using the throwaway
// test keys embedded in the Apex test classes. Output is pasted into
// JweInteropVectorsTest.cls as constants. Run once:
//   NODE_PATH=$(npm root -g) node scripts/generate-interop-vectors.mjs
import { CompactEncrypt, importJWK } from 'jose';

// Throwaway RSA-2048 test key. Never used outside the test suites.
const publicJwk = {
  kty: 'RSA',
  n: 'wD3pdCaSFdNajV-z1uU6wR-zbHTBg-17JJsxyjVxXhggOFYU6JJC6fMuri79leIEviMMsRUYH9qqX9LY2Dtcgafb-beYQ60PHRH8fTZS9894CKOLGEa-eAje7utAVaQrEWEnUFDIFdCbHAfQEzaB8wsj2d4-dF4OMc4R5An6ifqtWHsrJ8VWXfc_ywxTuuNzf_KcOpO3jTKXgB3_XI6oWujiHa_0LBBGJv9ngyCIb6ahU-baNhb2Fi5Ore1gSuTSL84m-1oj33LxWQdIqlsNTfSO54CqotWJmb6RWnjZiljB4PZMkJT0tzVY9ays05SNItoJMAzf5LErRMOm6zRVgQ',
  e: 'AQAB',
};

// Pre-shared key used by the Apex `dir` tests: MAC key || ENC key, hex.
const sharedKeyHex =
  'ABF71E6E95AD9B75EF5D44F0BA4CEB94FBADF9FD2DBC3F460C73A7E58D0BA984ECC904EC1DE279E2737EDC93D688879ABFF4DCB6AFEC3A6E9E8217FB17C0394C';

const enc = new TextEncoder();

async function rsa(alg, encAlg, kid, payload) {
  const key = await importJWK(publicJwk, alg);
  const token = await new CompactEncrypt(enc.encode(payload))
    .setProtectedHeader({ alg, enc: encAlg, kid })
    .encrypt(key);
  return token;
}

async function dir(encAlg, keyHex, kid, payload) {
  const key = Uint8Array.from(Buffer.from(keyHex, 'hex'));
  const token = await new CompactEncrypt(enc.encode(payload))
    .setProtectedHeader({ alg: 'dir', enc: encAlg, kid })
    .encrypt(key);
  return token;
}

const vectors = [
  ['RSA_OAEP_256_A256CBC_HS512', await rsa('RSA-OAEP-256', 'A256CBC-HS512', 'interop-3', 'RSA-OAEP-256 interop reference payload'), 'RSA-OAEP-256 interop reference payload'],
  ['RSA_OAEP_A128CBC_HS256', await rsa('RSA-OAEP', 'A128CBC-HS256', 'interop-4', 'RSA-OAEP A128 interop reference payload'), 'RSA-OAEP A128 interop reference payload'],
  ['DIR_A128CBC_HS256', await dir('A128CBC-HS256', sharedKeyHex.slice(0, 64), 'interop-5', 'dir A128 interop reference payload +/='), 'dir A128 interop reference payload +/='],
  ['RSA_OAEP_256_A128CBC_HS256', await rsa('RSA-OAEP-256', 'A128CBC-HS256', 'interop-6', 'OAEP-256 with A128 interop payload'), 'OAEP-256 with A128 interop payload'],
];

for (const [name, token, payload] of vectors) {
  console.log(`  private static final String ${name}_TOKEN = '${token}';`);
  console.log(`  private static final String ${name}_PAYLOAD = '${payload}';`);
}
