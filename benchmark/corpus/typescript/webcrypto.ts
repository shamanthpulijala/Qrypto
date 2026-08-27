// Benchmark corpus: TypeScript Web Crypto API patterns
// Expected detections marked with comments

// EXPECTED: RSA, vulnerable, public-key
async function generateRSAKey(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

// EXPECTED: ECDSA, vulnerable, signature
async function generateECDSAKey(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );
}

// EXPECTED: AES-GCM, adequate, symmetric
async function encryptAES(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  return await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: new Uint8Array(12) },
    key,
    data
  );
}

// EXPECTED: SHA-256, adequate, hash
async function hashSHA256(data: ArrayBuffer): Promise<ArrayBuffer> {
  return await crypto.subtle.digest('SHA-256', data);
}

// EXPECTED: SHA-1, classical-weak, hash
async function hashSHA1(data: ArrayBuffer): Promise<ArrayBuffer> {
  return await crypto.subtle.digest('SHA-1', data);
}

// No MD5 in Web Crypto API (it's not supported)
// This is a negative test case — should NOT produce MD5 finding

// EXPECTED: HMAC-SHA-256, adequate
async function createHMAC(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  return await crypto.subtle.sign('HMAC', key, data);
}
