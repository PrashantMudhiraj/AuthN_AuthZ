import dotenv from "dotenv";
dotenv.config({ path: "../.env" });

import express from "express";
import session from "express-session";
import * as oidc from "openid-client"; // Import as a namespace

const app = express();
const port = Number(process.env.PORT || 3000);
const client_id = process.env.CLIENT_ID;
const client_secret = process.env.CLIENT_SECRET;
const BASE_URL = `http://localhost:${port}`;

app.use(
    session({
        name: "bff-session",
        secret: "dev-secret",
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true, secure: false, sameSite: "lax" },
    }),
);

/* ===============================
   OIDC CONFIGURATION (v6)
================================ */
// In v6, discovery returns a configuration object used in helper functions
const serverConfig = await oidc.discovery(
    new URL("https://accounts.google.com/.well-known/openid-configuration"),
    client_id,
    client_secret,
);

/* ===============================
   LOGIN
================================ */
app.get("/login", async (req, res) => {
    const code_verifier = oidc.randomPKCECodeVerifier();
    const code_challenge = await oidc.calculatePKCECodeChallenge(code_verifier);

    // Store verifier in session
    req.session.code_verifier = code_verifier;

    const parameters = {
        redirect_uri: `${BASE_URL}/auth/callback`,
        scope: "openid profile email",
        code_challenge, //cryptographic challenge
        code_challenge_method: "S256",
    };

    const redirectTo = oidc.buildAuthorizationUrl(serverConfig, parameters);

    req.session.save(() => {
        res.redirect(redirectTo.href);
    });
});

/* ===============================
   CALLBACK
================================ */
app.get("/auth/callback", async (req, res, next) => {
    try {
        const currentUrl = new URL(
            req.protocol + "://" + req.get("host") + req.originalUrl,
        );

        const tokenSet = await oidc.authorizationCodeGrant(
            serverConfig,
            currentUrl,
            {
                pkceCodeVerifier: req.session.code_verifier,
                expectedRedirectUri: `${BASE_URL}/auth/callback`,
            },
        );

        // Get Claims (User Info)
        const claims = tokenSet.claims();
        req.session.user = claims;
        delete req.session.code_verifier;

        req.session.save(() => {
            res.redirect("/profile");
        });
    } catch (err) {
        next(err);
    }
});

app.get("/profile", (req, res) => {
    if (!req.session.user) return res.redirect("/login");
    res.json(req.session.user);
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.clearCookie("bff-session");
        // Redirect to Google's specific logout page
        // The 'continue' param tells Google where to send them after (requires registration)
        res.redirect("/logout-callback");
    });
});

// A simple landing page after the IdP logs the user out
app.get("/logout-callback", (req, res) => {
    res.send("You have been successfully logged out of all systems.");
});

app.listen(port, () => console.log(`App running at ${BASE_URL}`));
