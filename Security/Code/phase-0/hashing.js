import crypto from "crypto";
/**
 * crypt is a built in node.js module
 * Provides cryptographic primitives (hashing, encryption, random bytes)
 * No external npm package needed
 *
 * createHash('sha256'):
 *  - creates a hash function
 *  - sha256 is a cryptographic hash algorithm
 *  - output size : 256 bits
 *
 * update(password)
 *  - Feed input data into the hash function
 *  - You can call update() multiple times for streams
 *
 * digest('hex')
 *  - Finalize the hash
 *  - Converts binary output -> hex string(readable)
 *
 * Hashes the password
 * output looks random
 * Same input -> Same output
 *
 * In production, we do not use raw SHA-256 for passwords
 * We use bcrypt or argon
 */

function hashPassword(password) {
    const hash = crypto.createHash("sha256").update(password).digest("hex");
    console.log(hash);
    return hash;
}

hashPassword("password1234");
