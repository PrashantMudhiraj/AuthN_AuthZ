import jwt from "jsonwebtoken";

const JWT_SECRET = "secret";
const JWT_EXPIRY = "2m";

export function issueAccessToken(user) {
    const token = jwt.sign(
        {
            sub: user.id,
            email: user.email,
            role: user.role,
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY },
    );

    return token;
}

export function verifyAccessToken(token) {
    return jwt.verify(token, JWT_SECRET);
}
