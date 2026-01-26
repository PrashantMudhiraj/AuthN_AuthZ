import crypto from "crypto";

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
});

console.log({ privateKey, publicKey });

// Encrypt and Decrypt
const message = "hello world!";

const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(message));
/**
 *  - Anyone with public key can encrypt
 *  - Only private key owner can decrypt
 */

const decrypted = crypto.privateDecrypt(privateKey, encrypted);
/**
 *  - Only private key works
 *  - Public key cannot decrypt
 */

console.log(decrypted.toString());

// Sign and verify
// Data is open to all
const data = "important data";

const signature = crypto.sign("sha256", Buffer.from(data), privateKey);
/**
 *  - Uses private keys
 *  - Produces signature
 *  - Proves authenticity
 */

const isValid = crypto.verify(
    "sha256",
    Buffer.from(data),
    publicKey,
    signature,
);
/**
 *  - Anyone can verify
 *  - No on can forge without private key
 */

console.log(isValid);
