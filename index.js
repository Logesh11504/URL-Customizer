import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import shortid from "shortid";
import * as dotenv from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import path from "path";
import { fileURLToPath } from "url";
import connectPgSimple from "connect-pg-simple";

dotenv.config();

let app = express();

app.set("view engine", "ejs");
app.set("views", "./views");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

let port = process.env.PORT;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

pg.types.setTypeParser(1114, (stringValue) => {
  return stringValue;
});

const db = new pg.Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
  ssl: {
    ca: process.env.CA_CERT,
    rejectUnauthorized: true,
  },
});

db.on("connect", () => console.log("Database connected successfully"));
db.on("error", (err) => console.error("Database connection error:", err.stack));

const PgStore = connectPgSimple(session);

const maxAgeInMs = parseInt(process.env.MAX_AGE);

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
    store: new PgStore({
      pool: db,
      tableName: "session",
    }),
    cookie: {
      maxAge: maxAgeInMs,
      secure: true,
      sameSite: "none",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

const saltRounds = parseInt(process.env.SALT_ROUND);

app.get("/", async (req, res) => {
  res.render("about.ejs");
});

app.get("/register", async (req, res) => {
  let error = req.session.registerError;
  req.session.registerError = null;

  res.render("register.ejs", { error: error });
});

app.get("/login", async (req, res) => {
  const errorMessage = req.session.messages ? req.session.messages[0] : null;

  if (req.session.messages) {
    req.session.messages = [];
  }

  res.render("login.ejs", { error: errorMessage });
});

app.post("/register", async (req, res) => {
  const name = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  const uniqueUsername = name.replaceAll(" ", "_").toLowerCase();

  try {
    const emailCheckResult = await db.query(
      "SELECT * FROM user_credentials WHERE email = $1",
      [email]
    );

    if (emailCheckResult.rows.length > 0) {
      req.session.registerError =
        "Email already exists. Please try logging in.";
      return res.redirect("/register");
    }

    const usernameCheck = await db.query(
      "SELECT email FROM user_credentials WHERE username = $1",
      [uniqueUsername]
    );

    if (usernameCheck.rows.length > 0) {
      req.session.registerError = `The chosen username '${name}' is already taken. Please choose a different name.`;
      return res.redirect("/register");
    }

    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.error("Bcrypt Hashing Error:", err);
        req.session.registerError =
          "A security error occurred during registration.";
        return res.redirect("/register");
      }

      if (!hash) {
        console.error(
          "Bcrypt failed to produce a hash (hash is null/undefined). Check saltRounds value."
        );
        req.session.registerError =
          "Failed to secure the password. Please try again.";
        return res.redirect("/register");
      }

      try {
        const result = await db.query(
          "INSERT INTO user_credentials (email, password, username) VALUES ($1, $2, $3) RETURNING *",
          [email, hash, uniqueUsername]
        );
        const user = result.rows[0];

        req.login(user, (err) => {
          if (err) {
            console.error("Error logging in new user:", err);
            return res.redirect("/login");
          }
          res.redirect("/home");
        });
      } catch (dbErr) {
        console.error("Error inserting new user into database:", dbErr);
        req.session.registerError =
          "A database error occurred during final registration.";
        return res.redirect("/register");
      }
    });
  } catch (err) {
    console.error("Error during initial registration checks:", err);
    req.session.registerError =
      "An unexpected server error occurred during registration.";
    return res.redirect("/register");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/login",
    failureMessage: true,
  })
);

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/home",
  passport.authenticate("google", {
    successRedirect: "/home",
    failureRedirect: "/login",
  })
);

app.get("/home", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userEmail = req.user.email;
      const username = req.user.username;

      const fetch = await db.query(
        "SELECT * FROM links WHERE user_email = $1 ORDER BY click_count DESC",
        [userEmail]
      );

      const baseURL = `${req.protocol}://${req.get("host")}`;

      res.render("home.ejs", {
        allLinks: fetch.rows,
        baseURL: baseURL,
        username: username,
      });
    } catch (error) {
      console.error("Error fetching links:", error.stack);
      res.render("error.ejs", { error: error.message });
    }
  } else {
    res.redirect("/");
  }
});

app.post("/submit", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  try {
    const userEmail = req.user.email;
    const username = req.user.username;

    let shortcode = null;
    if (req.body.shortcode.trim().length > 0) {
      const check = await db.query(
        "SELECT short_code FROM links WHERE short_code = $1 AND user_email = $2",
        [req.body.shortcode.trim(), userEmail]
      );

      if (check.rows.length > 0) {
        return res.render("error.ejs", {
          error:
            "Custom shortcode is already in use by you. Please choose another.",
        });
      }

      shortcode = req.body.shortcode.trim();
    } else {
      let isUnique = false;
      while (!isUnique) {
        shortcode = shortid.generate();

        const check = await db.query(
          "SELECT short_code FROM links WHERE short_code = $1",
          [shortcode]
        );

        if (check.rows.length === 0) {
          isUnique = true;
        }
      }
    }

    await db.query(
      "INSERT INTO links (short_code, long_url, click_count, last_clicked, user_email) VALUES($1,$2,$3,$4,$5)",
      [shortcode, req.body.url.trim(), 0, "-", userEmail]
    );

    const fetch = await db.query(
      "SELECT * FROM links WHERE long_url = $1 AND short_code = $2 AND user_email = $3",
      [req.body.url.trim(), shortcode, userEmail]
    );

    if (fetch.rows.length === 0) {
      throw new Error("Failed to retrieve the newly created short link.");
    }

    const newShortUrl = `${req.protocol}://${req.get("host")}/${username}/${
      fetch.rows[0].short_code
    }`;

    res.render("submit.ejs", {
      short_url: newShortUrl,
      shortcode: fetch.rows[0].short_code,
      long_url: fetch.rows[0].long_url,
      total_click: fetch.rows[0].click_count,
      last_clicked: String(fetch.rows[0].last_clicked),
    });
  } catch (error) {
    console.error("Error submitting link:", error.stack);
    res.render("error.ejs", { error: error.message });
  }
});

app.get("/:username/:shortcode", async (req, res) => {
  try {
    const requestedShortcode = req.params.shortcode;
    const requestedUsername = req.params.username;

    const userResult = await db.query(
      "SELECT email FROM user_credentials WHERE username = $1",
      [requestedUsername]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).render("error.ejs", {
        error: `User '${requestedUsername}' not found.`,
      });
    }

    const userEmail = userResult.rows[0].email;

    const original_url_result = await db.query(
      "SELECT long_url from links WHERE short_code = $1 AND user_email = $2",
      [requestedShortcode, userEmail]
    );

    if (original_url_result.rows.length > 0) {
      await db.query(
        "UPDATE links SET click_count = click_count + 1, last_clicked = $1 WHERE short_code = $2 AND user_email = $3",
        [new Date().toLocaleString(), requestedShortcode, userEmail]
      );

      res.redirect(original_url_result.rows[0].long_url);
    } else {
      res.status(404).render("error.ejs", {
        error: `Short URL '${requestedShortcode}' for user '${requestedUsername}' not found.`,
      });
    }
  } catch (error) {
    console.error("Error processing shortcode request:", error.stack);
    res.render("error.ejs", { error: error.message });
  }
});

app.post("/delete/:username/:shortcode", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  try {
    const requestedUsername = req.params.username;
    const requestedShortcode = req.params.shortcode;
    const userEmail = req.user.email;

    if (req.user.username !== requestedUsername) {
      return res.status(403).render("error.ejs", {
        error: "Authorization error: Username mismatch.",
      });
    }

    const result = await db.query(
      "DELETE FROM links WHERE short_code = $1 AND user_email = $2 RETURNING *",
      [requestedShortcode, userEmail]
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .render("error.ejs", { error: "Link not found or already deleted." });
    }

    res.redirect("/home");
  } catch (error) {
    console.error("Error deleting link:", error.stack);
    res.render("error.ejs", { error: "An error occurred during deletion." });
  }
});

passport.use(
  new Strategy({ usernameField: "email" }, async function verify(
    username,
    password,
    cb
  ) {
    try {
      const result = await db.query(
        "SELECT * FROM user_credentials WHERE email = $1",
        [username]
      );

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;

        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(null, user);
            } else {
              return cb(null, false, { message: "Incorrect password." });
            }
          }
        });
      } else {
        return cb(null, false, {
          message: "User not found. Check email address.",
        });
      }
    } catch (err) {
      console.log(err);
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
      userprofileURL: process.env.USER_PROFILE_URL,
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      const result = await db.query(
        "SELECT * FROM user_credentials WHERE email = $1",
        [profile.email]
      );

      try {
        if (result.rows.length === 0) {
          let username = profile.displayName.replaceAll(" ", "_").toLowerCase();
          let uniqueUsername = username;
          let counter = 1;

          while (
            (
              await db.query(
                "SELECT email FROM user_credentials WHERE username = $1",
                [uniqueUsername]
              )
            ).rows.length > 0
          ) {
            uniqueUsername = `${username}_${counter}`;
            counter++;
          }

          const newUser = await db.query(
            "INSERT INTO user_credentials (email, password, username) VALUES ($1,$2,$3) RETURNING *",
            [profile.email, "google", uniqueUsername]
          );

          cb(null, newUser.rows[0]);
        } else {
          cb(null, result.rows[0]);
        }
      } catch (err) {
        cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user.email);
});

passport.deserializeUser(async (email, cb) => {
  try {
    const result = await db.query(
      "SELECT * FROM user_credentials WHERE email = $1",
      [email]
    );
    if (result.rows.length > 0) {
      const user = result.rows[0];
      cb(null, user);
    } else {
      cb(new Error("User not found during deserialization"));
    }
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server is Running Successfully on port ${port}`);
});