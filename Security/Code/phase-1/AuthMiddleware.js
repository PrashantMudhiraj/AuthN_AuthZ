import jwt from "jsonwebtoken";

const secret = "secret" || process.env.JWT_SECRET;

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: "Not authenticated" });
    }

    const token = authHeader.split(" ")[1];
    const payload = jwt.verify(token, secret);
    req.user = payload;
    next();
}

function authorize(requiredRole) {
    return (req, res, next) => {
        if (req.user.role !== requiredRole) {
            return res.status(403).json({ message: "Forbidden" });
        }
        next();
    };
}
