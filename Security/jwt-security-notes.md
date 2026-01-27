# JWT, RSA & API Security — Interview Preparation Notes

This document explains JWT, RSA, and API token validation with **brief but meaningful explanations**.  
Each section is short enough for revision, but deep enough for interviews.

---

## 1. Authentication vs Authorization

Authentication is the process of verifying the identity of a user or system.  
It answers the question: **“Who are you?”** and is usually done using credentials or tokens.

Authorization determines what an authenticated user is allowed to do.  
It answers the question: **“What can you access?”** and is enforced using roles, scopes, or permissions.

---

## 2. What is JWT (JSON Web Token)

JWT is a **self-contained, digitally signed token format** used to transfer identity and authorization data between parties.  
Because the token carries all required information, servers do not need to store session state.

JWTs are **signed, not encrypted** by default.  
This means the payload can be read by anyone, but **cannot be modified** without breaking the signature.

---

## 3. JWT Structure

A JWT consists of three Base64URL-encoded parts separated by dots:

```
HEADER.PAYLOAD.SIGNATURE
```

Each part has a clear responsibility:

- The **header** describes how the token was signed.
- The **payload** contains claims (user and context data).
- The **signature** ensures integrity and authenticity.

---

## 4. JWT Header

The header contains metadata required for token verification.

```json
{
    "alg": "RS256",
    "typ": "JWT",
    "kid": "auth-key-2025-01"
}
```

- `alg` tells the verifier which cryptographic algorithm was used.
- `kid` identifies which key signed the token, allowing correct key selection.

The header is not encrypted and must never be trusted without verification.

---

## 5. JWT Payload (Claims)

The payload contains claims about the subject and request context.

```json
{
    "sub": "user123",
    "scope": "order.read",
    "role": "ADMIN",
    "iss": "https://auth.company.com",
    "aud": "order-api",
    "exp": 1700003600
}
```

Claims are used by APIs to make authorization decisions.  
Because the payload is only encoded, **sensitive data must never be stored here**.

---

## 6. What an API Does to Validate a JWT

When an API receives a JWT, it does not trust it immediately.  
It first validates the token cryptographically and logically before allowing access.

The API performs these steps:

1. Extract the token from the `Authorization` header
2. Decode the header and payload
3. Validate the algorithm (`alg`)
4. Verify the signature
5. Validate claims such as `exp`, `iss`, and `aud`
6. Enforce authorization using roles or scopes

---

## 7. Hashing in JWT (RS256)

Before signing, the authorization server hashes the following string:

```
base64url(header) + "." + base64url(payload)
```

The hashing algorithm used is **SHA-256**.  
Hashing ensures that even a single-bit change in the token data will invalidate the signature.

---

## 8. Why Hashing is Required Before Signing

RSA is designed to work on fixed-size input and is computationally expensive.  
Hashing converts variable-length token data into a fixed-size digest.

This improves performance and ensures strong integrity guarantees.  
For this reason, JWTs always sign the **hash**, not the raw data.

---

## 9. What is RSA

RSA is an **asymmetric cryptographic algorithm** that uses a public/private key pair.  
The two keys are mathematically linked but cannot be derived from one another.

RSA enables secure systems without sharing secrets and is widely used in TLS, OAuth, and JWT.

---

## 10. Public Key vs Private Key

The **private key** is kept secret and is used to prove identity by signing data.  
The **public key** is shared and is used to verify that the data was signed by the correct private key.

This separation allows many systems to verify authenticity without risking key leakage.

---

## 11. RS256 in JWT (Digital Signatures)

RS256 combines **RSA** with **SHA-256** to create digital signatures.

### Signing (Authorization Server)

```
hash = SHA256(data)
signature = RSA_SIGN(hash, PRIVATE_KEY)
```

### Verification (API)

```
hash1 = SHA256(data)
hash2 = RSA_VERIFY(signature, PUBLIC_KEY)

hash1 == hash2 → token is valid
```

The API never creates signatures; it only verifies them.

---

## 12. Node.js Example — JWT Verification (RS256)

```js
const jwt = require("jsonwebtoken");
const fs = require("fs");

const PUBLIC_KEY = fs.readFileSync("./public.pem", "utf8");

jwt.verify(token, PUBLIC_KEY, {
    algorithms: ["RS256"],
    issuer: "https://auth.company.com",
    audience: "order-api",
});
```

This ensures the token was issued by a trusted authority and has not been tampered with.

---

## 13. Symmetric vs Asymmetric JWT Algorithms

**HS256** uses a shared secret for signing and verification.  
While simple, it becomes risky in distributed systems because the secret must be shared.

**RS256** separates responsibilities using public and private keys.  
Only the auth server can issue tokens, while many APIs can safely verify them.

---

## 14. What is `kid` (Key ID)

`kid` identifies which cryptographic key was used to sign the token.

```json
{
    "alg": "RS256",
    "kid": "auth-key-2025-01"
}
```

It allows APIs to select the correct public key, especially during key rotation.

---

## 15. JWKS (JSON Web Key Set)

JWKS is a public endpoint that exposes one or more public signing keys.

```
https://auth.company.com/.well-known/jwks.json
```

APIs fetch this endpoint, match the `kid`, and verify the token using the correct key.

---

## 16. SSL/TLS vs JWT (Common Interview Topic)

SSL/TLS uses RSA primarily for **confidentiality**.  
The public key encrypts data, and the private key decrypts it.

JWT uses RSA for **authenticity and integrity**.  
The private key signs the token, and the public key verifies it.

---

## 17. Roles in a JWT System

- **Authorization Server** issues and signs tokens.
- **Client** carries the token and sends it with requests.
- **API (Resource Server)** verifies the token and enforces access rules.

The client is never trusted to create or modify tokens.

---

## 18. Key Interview Takeaways

JWTs are signed, not encrypted.  
APIs must always verify signatures and claims before trusting a token.  
RS256 is preferred for enterprise and microservice architectures.

Security comes from cryptography, not from trusting the client.

---

## 19. Final Interview Answer

JWT provides stateless authentication using digital signatures.  
In RS256, the authorization server signs the token using a private key, and APIs verify it using the corresponding public key by recomputing the hash and validating the signature.  
This design ensures integrity, authenticity, and scalability without shared secrets.
