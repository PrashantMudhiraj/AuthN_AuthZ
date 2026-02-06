import { verifyAccessToken } from "../utility/jwt.js";

export function authenticate(req, res, next) {
    // console.log(req.headers);
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        req.user = null;
        return next();
    }

    const token = authHeader?.split(" ")[1];
    // console.log("token", token);

    try {
        const decoded = verifyAccessToken(token);
        console.log(decoded);
        req.user = {
            id: decoded.sub,
            email: decoded.email,
            role: decoded.role,
        };
    } catch (err) {
        console.log(err);
        req.user = null;
    }
    next();
}
