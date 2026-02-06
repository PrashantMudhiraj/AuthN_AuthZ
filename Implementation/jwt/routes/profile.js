import express from "express";
import { requireAuth } from "../middlewares/requireAuth.js";

const router = express.Router();

router.get("/info", requireAuth, (req, res) => {
    res.json({
        message: " This is a protected route",
        user: req.user,
    });
});

export default router;
