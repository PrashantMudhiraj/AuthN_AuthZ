import bcrypt from "bcrypt";

const users = [
    {
        id: "u1",
        email: "user1@example.com",
        role: "user",
        passwordHash: bcrypt.hashSync("password123", 10),
    },
    {
        id: "u2",
        email: "user2@example.com",
        role: "admin",
        passwordHash: bcrypt.hashSync("password123", 10),
    },
];

export function findUserByEmail(email) {
    return users.find((user) => user.email === email);
}
