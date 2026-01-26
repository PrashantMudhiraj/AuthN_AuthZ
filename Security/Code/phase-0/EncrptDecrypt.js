import crypto from "crypto";

/**
 * crypto.randomBytes(32)
 *  - Generate a random symmetric key
 *  - 32 bytes = 256 bits
 *  - Used by AES-256
 *
 * crypto.randomBytes(16)
 *  - IV = Initializer vector
 *  - Adds randomness
 *  - Prevents identical plaintext from production identical ciphertext
 *  - IV is not secret, but must be unique
 *
 * crypto.createCipheriv('aes-256-cbc', key, iv);
 *  - Creates an AES cipher
 *  - aes-256-cbc
 *      - AES algorithm
 *      - 256-bits
 *      - CBC mode -> Cipher Blocking chain
 *          - CBC is used here for demo; GCM is preferred in real systems
 * crypto.update(text,'utf-8','hex') + cipher.final('hex');
 *  - update() -> encrypt data
 *  - utf-8 -> input encoding
 *  - hex -> output encoding
 *  - final() -> finishes encryption
 *
 * crypto.createDecipher('aes-256-cbc', key, iv);
 *  - Uses same algorithm
 *  - Uses same key
 *  - Uses same IV
 *
 * - This is why symmetric crypto is called symmetric
 */

const key = crypto.randomBytes(32);
console.log(key);
const iv = crypto.randomBytes(16);
console.log(iv);

function encrypt(text) {
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    return cipher.update(text, "utf-8", "hex") + cipher.final("hex");
}

function decrypt(encrypted) {
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    return decipher.update(encrypted, "hex", "utf-8") + decipher.final("utf-8");
}

const secret = encrypt("hello");
console.log(decrypt(secret));

/**
 * Block Cipher : An Encryption algorithm that works on fixed-size blocks of data. Can encrypt only one block at a time.
 * Block Cipher Mode : A method that tells the cipher how to encrypt data longer than one block. (CBC one of them)
 * CBC (Cipher Block Chaining) : A block cipher mode of operation
 *  - CBC chains blocks together so that:
 *      - Each block depends on the previous block
 * IV (Initialization vector) : A random value used only for first block of operation
 * - Ciphertext[i] = Encrypt( Plaintext[i] XOR Ciphertext[i-1] )
 * - Ciphertext[1] = Encrypt( Plaintext[1] XOR IV ) -> for block one (It acts as a fake previous block)
 *
 */
