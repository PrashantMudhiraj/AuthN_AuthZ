import bcrypt from "bcrypt";

const users = [
    {
        id: "u1",
        email: "user1@example.com",
        role: "user",
        passwordHash: bcrypt.hashSync("password123", 10),
    },
];

export function findUserByEmail(email) {
    return users.find((user) => user.email === email);
}
