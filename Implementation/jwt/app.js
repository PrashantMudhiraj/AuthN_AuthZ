import express from "express";
import { authenticate } from "./middlewares/authenticate.js";
import authRouter from "./routes/auth.js";
import profileRouter from "./routes/profile.js";

const app = express();

app.use(express.json());
app.use(authenticate);

app.use("/auth", authRouter);
app.use("/profile", profileRouter);
app.listen(3000);
