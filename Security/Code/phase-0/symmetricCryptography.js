import crypto from "crypto";

const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    const encrypted = cipher.update(text, "utf8", "hex") + cipher.final("hex");

    const authTag = cipher.getAuthTag();

    return {
        encrypted,
        iv: iv.toString("hex"),
        authTag: authTag.toString("hex"),
    };
}

function decrypt({ encrypted, iv, authTag }) {
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key, // same key
        Buffer.from(iv, "hex"), // same IV
    );

    decipher.setAuthTag(Buffer.from(authTag, "hex"));

    return decipher.update(encrypted, "hex", "utf8") + decipher.final("utf8");
}

const enc = encrypt("hello");
console.log(enc);
const data = decrypt(enc);

console.log(data);

/**
 * Same key encrypts & decrypts
 * IV must be unique
 * Auth Tah ensures:
 *  - Data was not modified
 *  - Wrong key = decryption fails
 *
 */
