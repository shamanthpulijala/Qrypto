// Benchmark corpus: JavaScript/Node.js cryptographic patterns
// Expected detections marked with comments

const crypto = require('crypto');

// EXPECTED: RSA, vulnerable, public-key
const { privateKey, publicKey } = crypto.generateKeyPairSync('RSA', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// EXPECTED: RSA-SHA256, vulnerable, signature
const sign = crypto.createSign('RSA-SHA256');
sign.update('data to sign');
const signature = sign.sign(privateKey, 'hex');

// EXPECTED: AES-256-GCM, adequate, symmetric
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

// EXPECTED: SHA-256, adequate, hash
const hash = crypto.createHash('sha256').update('test').digest('hex');

// EXPECTED: SHA-1, classical-weak, hash
const weakHash = crypto.createHash('sha1').update('test').digest('hex');

// EXPECTED: MD5, classical-weak, hash (critical severity)
const brokenHash = crypto.createHash('md5').update('test').digest('hex');

// EXPECTED: Private Key, secret
const hardcodedKey = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...';
