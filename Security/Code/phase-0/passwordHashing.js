import bcrypt from "bcrypt";

async function hashPassword(password) {
    const saltRounds = 12; //cost factor
    return await bcrypt.hash(password, saltRounds); // 2 ^ 12 -> 1024 iterations
}

/**
 * What happens internally
 *  - Generate salt
 *  - Applies key stretching
 *  - Store slat inside hash string
 */
//output of hashPassword
//$2b$12$Z31ROzNtbv2SEhjpEiVcMezyMdqYShKkVmGBai9qDTjjyZGZ3fKj6

async function verifyPassword(password, storedHash) {
    console.log(storedHash);
    return await bcrypt.compare(password, storedHash);
}

/**
 *  - Hashes input password
 *  - Extracts salt from stored hash
 *  - Compare securely
 *  - Returns true/false
 */

const password = "Prashant";
const isPasswordVerified = await verifyPassword(
    password,
    await hashPassword(password), // Get storedHash from database using userName or userId
);

console.log(isPasswordVerified);
//passwords are verified, not recovered
/**
 *  - Cost Factor
 *      - A parameter that controls how slow the hashing operation is
 *  - Work Factor
 *      - another name for cost factor - how much computation work is required
 *  - Salt Rounds
 *      - in bcrypt, the logarithms cost factor that determines
 *          - how many times the hashing algorithm internally runs
 *  - Cost = 2 ^ saltRounds
 *      - saltRounds = 10 -> 1024 iterations
 *      - saltRounds = 12 -> 4096 iterations
 *      - saltRounds = 14 -> 16384 iterations
 *
 *  - Why Salt Rounds Exist (Security Reason)
 *      - Threat model
 *      - Attackers
 *          - Have powerful CPUs/GPUs
 *          - Can try billions of guesses per second
 *  - bcrypt's defense
 *      - Internally
 *          - Runs slow
 *          - Users repeated hashing
 *          - Makes brute-force expensive
 * - password + salt
 *      |
 *      hash
 *      |
 *      hash
 *      |
 *      hash (2 ^ saltRounds times)
 *  - Salt is generated once
 *  - Hashing is repeated exponentially
 *  - This is called key stretching
 *  - The same salt is used for all hashing rounds in bcrypt
 *
 *  - $2b$12$<salt><hash>
 *  - 2b -> bcrypt version
 *  - 12 -> cost factor (saltRounds)
 *  - <salt> -> single salt
 *  - <hash> -> final derived hash
 */
