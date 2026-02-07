import express from "express";
import { authenticate } from "./middlewares/authenticate.js";
import authRouter from "./routes/auth.js";
import profileRouter from "./routes/profile.js";
import { requireRole } from "./middlewares/requireRole.js";

const app = express();

app.use(express.json());
app.use(authenticate);

app.use("/auth", authRouter);
app.use("/profile", profileRouter);
app.post("/admin", requireRole("admin"), (req, res) => {
    res.status(200).json({
        message: "RBAC Route",
    });
});
app.listen(3000);
