import express from "express";
import bcrypt from "bcrypt";
import { issueAccessToken } from "../utility/jwt.js";
import { findUserByEmail } from "../data/users.js";

const router = express.Router();

router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(401).json({ error: "Invalid Cred" });
    }

    const user = findUserByEmail(email);

    if (!user) {
        return res.status(401).json({ error: "Invalid Cred" });
    }

    // console.log(password, user);
    const isValid = await bcrypt.compare(password, user.passwordHash);

    if (!isValid) {
        return res.status(401).json({ error: "Invalid Cred" });
    }

    const accessToken = issueAccessToken(user);

    res.json({ accessToken });
});

export default router;
