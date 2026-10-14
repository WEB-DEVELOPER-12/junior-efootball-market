 require("dotenv").config();
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const multer = require("multer");
const uploadDir = path.join(__dirname, "public", "uploads");
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const extension = path.extname(file.originalname).toLowerCase();
        const filename = `listing-${Date.now()}-${Math.round(Math.random() * 1e9)}${extension}`;
        cb(null, filename);
    }
});
const upload = multer({
    storage,
    limits: {
        fileSize: 5 * 1024 * 1024
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/webp"
        ];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error("Only JPG, PNG, and WebP images are allowed."));
        }
        cb(null, true);
    }
});
const nodemailer = require("nodemailer");
const db = require("./database");
const adminRoutes = require("./admin-routes");
const app = express();
const PORT = process.env.PORT || 3000;
// ===============================
// EMAIL CONFIGURATION
// ===============================
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT) || 587,
    secure: Number(process.env.EMAIL_PORT) === 465,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
// ===============================
// MIDDLEWARE
// ===============================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
if (process.env.NODE_ENV === "production" && !process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET must be configured in production.");
}

app.set("trust proxy", process.env.NODE_ENV === "production" ? 1 : false);

app.use(
    session({
        name: "jem.sid",
        secret: process.env.SESSION_SECRET || require("crypto").randomBytes(32).toString("hex"),
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 1000 * 60 * 60 * 24
        }
    })
);
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/admin", adminRoutes);
// ===============================
// HOME
// ===============================
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});
// ===============================
// UPDATE MY PROFILE
// ===============================
app.put("/api/profile", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in to update your profile."
        });
    }

    const profileInfo = req.body.profile_info;

    if (typeof profileInfo !== "string" || profileInfo.length > 500) {
        return res.status(400).json({
            success: false,
            message: "About You must be text with a maximum of 500 characters."
        });
    }

    db.run(
        "UPDATE users SET profile_info = ? WHERE id = ?",
        [profileInfo.trim(), req.session.user.id],
        function (err) {
            if (err) {
                console.error("Profile update error:", err.message);
                return res.status(500).json({
                    success: false,
                    message: "Could not save your profile. Please try again."
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: "User account was not found."
                });
            }

            return res.json({
                success: true,
                message: "Profile saved successfully."
            });
        }
    );
});

// ===============================
// SERVER STATUS
// ===============================
app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        message: "Junior eFootball Market server is running!",
        database: "connected"
    });
});
// ===============================
// CREATE ACCOUNT
// ===============================
app.post("/api/register", async (req, res) => {
    try {
        const {
            username,
            email,
            password,
            confirmPassword,
            agreeRules
        } = req.body;
        if (!username || !email || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Please fill in all required fields."
            });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Passwords do not match."
            });
        }
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 8 characters long."
            });
        }
        if (
            agreeRules !== true &&
            agreeRules !== "true" &&
            agreeRules !== "on"
        ) {
            return res.status(400).json({
                success: false,
                message: "You must agree to the Marketplace Rules."
            });
        }
        const cleanUsername = username.trim();
        const cleanEmail = email.trim().toLowerCase();
        if (cleanUsername.length < 3) {
            return res.status(400).json({
                success: false,
                message: "Username must be at least 3 characters long."
            });
        }
        db.get(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            [cleanUsername, cleanEmail],
            async (err, existingUser) => {
                if (err) {
                    console.error("Registration lookup error:", err);
                    return res.status(500).json({
                        success: false,
                        message: "Server error. Please try again."
                    });
                }
                if (existingUser) {
                    return res.status(409).json({
                        success: false,
                        message: "Username or email is already registered."
                    });
                }
                try {
                    const hashedPassword = await bcrypt.hash(
                        password,
                        12
                    );
                    db.run(
                        `INSERT INTO users
                        (username, email, password, role, status)
                        VALUES (?, ?, ?, 'user', 'active')`,
                        [
                            cleanUsername,
                            cleanEmail,
                            hashedPassword
                        ],
                        function (insertErr) {
                            if (insertErr) {
                                console.error(
                                    "Registration error:",
                                    insertErr
                                );
                                return res.status(500).json({
                                    success: false,
                                    message: "Could not create account."
                                });
                            }
                            res.status(201).json({
                                success: true,
                                message:
                                    "Account created successfully. You can now log in."
                            });
                        }
                    );
                } catch (hashError) {
                    console.error(
                        "Password hashing error:",
                        hashError
                    );
                    res.status(500).json({
                        success: false,
                        message: "Could not create account."
                    });
                }
            }
        );
    } catch (error) {
        console.error(
            "Registration server error:",
            error
        );
        res.status(500).json({
            success: false,
            message: "Server error. Please try again."
        });
    }
});
// ===============================
// LOGIN
// ===============================
app.post("/api/login", (req, res) => {
    const { login, password } = req.body;
    if (!login || !password) {
        return res.status(400).json({
            success: false,
            message:
                "Please enter your username/email and password."
        });
    }
    const loginValue = login.trim();
    db.get(
        `SELECT id, username, email, password, role, status
         FROM users
         WHERE username = ? OR email = ?`,
        [
            loginValue,
            loginValue.toLowerCase()
        ],
        async (err, user) => {
            if (err) {
                console.error(
                    "Login lookup error:",
                    err
                );
                return res.status(500).json({
                    success: false,
                    message:
                        "Server error. Please try again."
                });
            }
            if (!user) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid login details."
                });
            }
            if (user.status !== "active") {
                return res.status(403).json({
                    success: false,
                    message:
                        "This account is not currently active."
                });
            }
            const passwordMatches =
                await bcrypt.compare(
                    password,
                    user.password
                );
            if (!passwordMatches) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid login details."
                });
            }
            const loggedInUser = {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            };

            req.session.regenerate((sessionErr) => {
                if (sessionErr) {
                    console.error("Session regeneration error:", sessionErr);
                    return res.status(500).json({
                        success: false,
                        message: "Could not complete login. Please try again."
                    });
                }

                req.session.user = loggedInUser;
                req.session.save((saveErr) => {
                    if (saveErr) {
                        console.error("Session save error:", saveErr);
                        return res.status(500).json({
                            success: false,
                            message: "Could not complete login. Please try again."
                        });
                    }

                    res.json({
                        success: true,
                        message: "Login successful.",
                        user: loggedInUser
                    });
                });
            });
        }
    );
});
// ===============================
// FORGOT PASSWORD
// ===============================
app.post("/api/forgot-password", (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({
            success: false,
            message: "Please enter your email address."
        });
    }
    const cleanEmail = email.trim().toLowerCase();
    db.get(
        "SELECT id, username, email FROM users WHERE email = ?",
        [cleanEmail],
        (err, user) => {
            if (err) {
                console.error(
                    "Forgot password lookup error:",
                    err
                );
                return res.status(500).json({
                    success: false,
                    message: "Server error. Please try again."
                });
            }
            // Do not reveal whether an email exists.
            if (!user) {
                return res.json({
                    success: true,
                    message:
                        "If an account with that email exists, a password reset link has been sent. Please check your inbox and spam folder."
                });
            }
            const resetToken =
                crypto.randomBytes(32).toString("hex");
            const resetExpires =
                Date.now() + 1000 * 60 * 15;
            db.run(
                `UPDATE users
                 SET reset_token = ?, reset_expires = ?
                 WHERE id = ?`,
                [
                    resetToken,
                    resetExpires,
                    user.id
                ],
                async (updateErr) => {
                    if (updateErr) {
                        console.error(
                            "Reset token error:",
                            updateErr
                        );
                        return res.status(500).json({
                            success: false,
                            message:
                                "Could not create password reset request."
                        });
                    }
                    const appUrl =
                        process.env.APP_URL ||
                        `http://localhost:${PORT}`;
                    const resetLink =
                        `${appUrl}/reset-password.html?token=${resetToken}`;
                    try {
                        await transporter.sendMail({
                            from:
                                process.env.EMAIL_FROM ||
                                process.env.EMAIL_USER,
                            to: user.email,
                            subject:
                                "Junior eFootball Market - Password Reset",
                            text:
                                `Hello ${user.username},\n\n` +
                                `We received a request to reset your Junior eFootball Market password.\n\n` +
                                `Use this link to create a new password:\n${resetLink}\n\n` +
                                `This link will expire in 15 minutes.\n\n` +
                                `If you did not request this password reset, you can ignore this email.\n\n` +
                                `Junior eFootball Market`,
                            html: `
                                <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:20px;">
                                    <h2>⚽ Junior eFootball Market</h2>
                                    <p>Hello ${user.username},</p>
                                    <p>
                                        We received a request to reset your
                                        Junior eFootball Market password.
                                    </p>
                                    <p>
                                        Click the button below to create a new password:
                                    </p>
                                    <p>
                                        <a
                                            href="${resetLink}"
                                            style="
                                                display:inline-block;
                                                background:#28a745;
                                                color:white;
                                                padding:12px 20px;
                                                text-decoration:none;
                                                border-radius:6px;
                                                font-weight:bold;
                                            "
                                        >
                                            Reset Password
                                        </a>
                                    </p>
                                    <p>
                                        This link will expire in
                                        <strong>15 minutes</strong>.
                                    </p>
                                    <p>
                                        If you did not request this password reset,
                                        you can safely ignore this email.
                                    </p>
                                    <hr>
                                    <p style="font-size:12px;color:#777;">
                                        Never share your eFootball/Konami password,
                                        M-Pesa PIN, OTP, or other sensitive credentials.
                                    </p>
                                </div>
                            `
                        });
                        console.log(
                            `Password reset email sent to ${user.email}.`
                        );
                        return res.json({
                            success: true,
                            message:
                                "If an account with that email exists, a password reset link has been sent. Please check your inbox and spam folder."
                        });
                    } catch (emailError) {
                        console.error(
                            "Password reset email error:",
                            emailError
                        );
                        // Remove the unused reset token if email delivery fails.
                        db.run(
                            `UPDATE users
                             SET reset_token = NULL,
                                 reset_expires = NULL
                             WHERE id = ?`,
                            [user.id],
                            (clearErr) => {
                                if (clearErr) {
                                    console.error(
                                        "Could not clear reset token:",
                                        clearErr
                                    );
                                }
                            }
                        );
                        return res.status(500).json({
                            success: false,
                            message:
                                "We could not send the password reset email right now. Please try again later."
                        });
                    }
                }
            );
        }
    );
});
// ===============================
// RESET PASSWORD
// ===============================
app.post("/api/reset-password", async (req, res) => {
    try {
        const {
            token,
            password,
            confirmPassword
        } = req.body;
        if (!token || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Please fill in all fields."
            });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Passwords do not match."
            });
        }
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message:
                    "Password must be at least 8 characters long."
            });
        }
        db.get(
            `SELECT id
             FROM users
             WHERE reset_token = ?
             AND reset_expires > ?`,
            [
                token,
                Date.now()
            ],
            async (err, user) => {
                if (err) {
                    console.error(
                        "Reset password lookup error:",
                        err
                    );
                    return res.status(500).json({
                        success: false,
                        message:
                            "Server error. Please try again."
                    });
                }
                if (!user) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "This password reset link is invalid or has expired."
                    });
                }
                const hashedPassword =
                    await bcrypt.hash(password, 12);
                db.run(
                    `UPDATE users
                     SET password = ?,
                         reset_token = NULL,
                         reset_expires = NULL
                     WHERE id = ?`,
                    [
                        hashedPassword,
                        user.id
                    ],
                    (updateErr) => {
                        if (updateErr) {
                            console.error(
                                "Password update error:",
                                updateErr
                            );
                            return res.status(500).json({
                                success: false,
                                message:
                                    "Could not reset your password."
                            });
                        }
                        res.json({
                            success: true,
                            message:
                                "Password reset successfully. You can now log in."
                        });
                    }
                );
            }
        );
    } catch (error) {
        console.error(
            "Reset password server error:",
            error
        );
        res.status(500).json({
            success: false,
            message:
                "Server error. Please try again."
        });
    }
});
// ===============================
// LOGOUT
// ===============================
app.post("/api/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(
                "Logout error:",
                err
            );
            return res.status(500).json({
                success: false,
                message:
                    "Could not log out."
            });
        }
        res.clearCookie("jem.sid", { path: "/" });
        res.json({
            success: true,
            message:
                "Logged out successfully."
        });
    });
});
// ===============================
// ADVERTISING CREDITS — API
// ===============================
// Get available advertising packages
app.get("/api/advertising/packages", (req, res) => {
    db.all(
        `
        SELECT id, name, price, credits
        FROM advertising_packages
        WHERE is_active = 1
        ORDER BY price ASC
        `,
        [],
        (err, packages) => {
            if (err) {
                console.error("Advertising packages error:", err);
                return res.status(500).json({
                    success: false,
                    message: "Could not load advertising packages."
                });
            }
            res.json({
                success: true,
                packages
            });
        }
    );
});
// Get current user's advertising credit balance
app.get("/api/advertising/credits", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in first."
        });
    }
    db.get(
        `
        SELECT credits
        FROM advertising_credits
        WHERE user_id = ?
        `,
        [req.session.user.id],
        (err, row) => {
            if (err) {
                console.error("Advertising credits error:", err);
                return res.status(500).json({
                    success: false,
                    message: "Could not load your advertising credits."
                });
            }
            res.json({
                success: true,
                credits: row ? row.credits : 0
            });
        }
    );
});
// Submit an M-Pesa payment for advertising credits
app.post("/api/advertising/payments", upload.single("screenshot"), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in before submitting a payment."
        });
    }
    const {
        full_name,
        whatsapp_number,
        email,
        package_id,
        transaction_code
    } = req.body;
    const fullName = full_name
        ? String(full_name).trim()
        : "";
    const whatsappNumber = whatsapp_number
        ? String(whatsapp_number).trim()
        : "";
    const emailAddress = email
        ? String(email).trim().toLowerCase()
        : "";
    const packageId = Number(package_id);
    const transactionCode = transaction_code
        ? String(transaction_code).trim().toUpperCase()
        : "";
    if (!fullName) {
        return res.status(400).json({
            success: false,
            message: "Please enter your full name."
        });
    }
    if (!whatsappNumber) {
        return res.status(400).json({
            success: false,
            message: "Please enter your WhatsApp number."
        });
    }
    if (!emailAddress) {
        return res.status(400).json({
            success: false,
            message: "Please enter your email address."
        });
    }
    if (!Number.isInteger(packageId) || packageId <= 0) {
        return res.status(400).json({
            success: false,
            message: "Please select a valid advertising package."
        });
    }
    if (!transactionCode) {
        return res.status(400).json({
            success: false,
            message: "Please enter your M-Pesa transaction code."
        });
    }
    if (!req.file) {
        return res.status(400).json({
            success: false,
            message: "Please upload your payment screenshot."
        });
    }
    const screenshotPath = "/uploads/" + req.file.filename;
    db.get(
        `
        SELECT id, name, price, credits
        FROM advertising_packages
        WHERE id = ?
          AND is_active = 1
        `,
        [packageId],
        (packageErr, packageRow) => {
            if (packageErr) {
                console.error(
                    "Advertising package lookup error:",
                    packageErr
                );
                return res.status(500).json({
                    success: false,
                    message: "Could not verify the selected package."
                });
            }
            if (!packageRow) {
                return res.status(404).json({
                    success: false,
                    message: "The selected package is not available."
                });
            }
            db.get(
                `
                SELECT id
                FROM advertising_payments
                WHERE transaction_code = ?
                `,
                [transactionCode],
                (duplicateErr, duplicateRow) => {
                    if (duplicateErr) {
                        console.error(
                            "Advertising payment duplicate check error:",
                            duplicateErr
                        );
                        return res.status(500).json({
                            success: false,
                            message:
                                "Could not verify the transaction code."
                        });
                    }
                    if (duplicateRow) {
                        return res.status(409).json({
                            success: false,
                            message:
                                "This M-Pesa transaction code has already been submitted."
                        });
                    }
                    db.run(
                        `
                        INSERT INTO advertising_payments (
                            user_id,
                            package_id,
                            amount,
                            transaction_code,
                            status,
                            full_name,
                            whatsapp_number,
                            email,
                            screenshot
                        )
                        VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
                        `,
                        [
                            req.session.user.id,
                            packageRow.id,
                            packageRow.price,
                            transactionCode,
                            fullName,
                            whatsappNumber,
                            emailAddress,
                            screenshotPath
                        ],
                        function (insertErr) {
                            if (insertErr) {
                                console.error(
                                    "Advertising payment insert error:",
                                    insertErr
                                );
                                return res.status(500).json({
                                    success: false,
                                    message:
                                        "Could not submit your payment."
                                });
                            }
                            res.status(201).json({
                                success: true,
                                message:
                                    "Payment submitted successfully. Please wait for admin verification.",
                                payment: {
                                    id: this.lastID,
                                    package: packageRow.name,
                                    amount: packageRow.price,
                                    credits: packageRow.credits,
                                    status: "pending",
                                    screenshot: screenshotPath
                                }
                            });
                        }
                    );
                }
            );
        }
    );
});
// Get current user's advertising payment history
app.get("/api/advertising/payments", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in first."
        });
    }
    db.all(
        `
        SELECT
            advertising_payments.id,
            advertising_payments.amount,
            advertising_payments.transaction_code,
            advertising_payments.status,
            advertising_payments.reviewed_at,
            advertising_payments.created_at,
            advertising_packages.name AS package_name,
            advertising_packages.credits
        FROM advertising_payments
        JOIN advertising_packages
            ON advertising_packages.id = advertising_payments.package_id
        WHERE advertising_payments.user_id = ?
        ORDER BY advertising_payments.created_at DESC
        `,
        [req.session.user.id],
        (err, payments) => {
            if (err) {
                console.error(
                    "Advertising payment history error:",
                    err
                );
                return res.status(500).json({
                    success: false,
                    message: "Could not load your payment history."
                });
            }
            res.json({
                success: true,
                payments
            });
        }
    );
});
// ===============================
// CURRENT USER
// ===============================
app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "You are not logged in."
        });
    }

    db.get(
        "SELECT id, username, email, role, profile_info FROM users WHERE id = ?",
        [req.session.user.id],
        (err, user) => {
            if (err) {
                console.error("Profile lookup error:", err.message);
                return res.status(500).json({
                    success: false,
                    message: "Could not load your profile."
                });
            }

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: "User account was not found."
                });
            }

            res.json({
                success: true,
                user: user
            });
        }
    );
});
// ===============================
// MARKETPLACE — CREATE LISTING
// ===============================
app.post("/api/listings", upload.single("image"), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in before posting an advertisement."
        });
    }
    const {
        title,
        description,
        category,
        price,
        collective_strength,
        team_name,
        player_count,
        featured_player,
        account_level,
        platform
    } = req.body;
    if (!title || !description || !category || price === undefined || price === "") {
        return res.status(400).json({
            success: false,
            message: "Please fill in all required advertisement fields."
        });
    }
    const cleanTitle = String(title).trim();
    const cleanDescription = String(description).trim();
    const cleanCategory = String(category).trim();
    const cleanTeam = team_name ? String(team_name).trim() : null;
    const cleanFeaturedPlayer = featured_player ? String(featured_player).trim() : null;
    const cleanAccountLevel = account_level ? String(account_level).trim() : null;
    const cleanPlatform = platform ? String(platform).trim() : null;
    const numericPrice = Number(price);
    const numericStrength =
        collective_strength === "" || collective_strength === undefined
            ? null
            : Number(collective_strength);
    const numericPlayerCount =
        player_count === "" || player_count === undefined
            ? null
            : Number(player_count);
    if (!cleanTitle || !cleanDescription || !cleanCategory) {
        return res.status(400).json({
            success: false,
            message: "Please fill in all required advertisement fields."
        });
    }
    if (!Number.isFinite(numericPrice) || numericPrice < 0) {
        return res.status(400).json({
            success: false,
            message: "Please enter a valid price."
        });
    }
    if (
        numericStrength !== null &&
        (!Number.isFinite(numericStrength) || numericStrength < 0)
    ) {
        return res.status(400).json({
            success: false,
            message: "Please enter a valid collective strength."
        });
    }
    if (
        numericPlayerCount !== null &&
        (!Number.isInteger(numericPlayerCount) || numericPlayerCount < 0)
    ) {
        return res.status(400).json({
            success: false,
            message: "Please enter a valid player count."
        });
    }
    const userId = req.session.user.id;
    // Reserve one credit before publishing, preventing simultaneous
    // requests from spending the same last credit.
    db.run(
        `
        UPDATE advertising_credits
        SET credits = credits - 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
          AND credits > 0
        `,
        [userId],
        function (creditErr) {
            if (creditErr) {
                console.error("Advertising credit check error:", creditErr);
                return res.status(500).json({
                    success: false,
                    message: "Could not verify your advertising credits."
                });
            }
            if (this.changes !== 1) {
                return res.status(403).json({
                    success: false,
                    message: "You need at least 1 advertising credit to publish an advertisement."
                });
            }
            let imagePath = null;
            if (req.file) {
                imagePath = "/uploads/" + req.file.filename;
            }
            const sql = `
                INSERT INTO listings (
                    user_id,
                    title,
                    description,
                    category,
                    price,
                    image,
                    collective_strength,
                    team_name,
                    player_count,
                    featured_player,
                    account_level,
                    platform,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            `;
            const values = [
                userId,
                cleanTitle,
                cleanDescription,
                cleanCategory,
                numericPrice,
                imagePath,
                numericStrength,
                cleanTeam,
                numericPlayerCount,
                cleanFeaturedPlayer,
                cleanAccountLevel,
                cleanPlatform
            ];
            db.run(sql, values, function (insertErr) {
                if (insertErr) {
                    console.error("Create listing error:", insertErr);
                    // Restore the reserved credit if publishing fails.
                    return db.run(
                        `
                        UPDATE advertising_credits
                        SET credits = credits + 1,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = ?
                        `,
                        [userId],
                        (refundErr) => {
                            if (refundErr) {
                                console.error(
                                    "CRITICAL: Could not restore advertising credit:",
                                    refundErr
                                );
                            }
                            return res.status(500).json({
                                success: false,
                                message: refundErr
                                    ? "Publishing failed and credit restoration needs admin attention."
                                    : "Could not publish the advertisement. Your credit has been restored."
                            });
                        }
                    );
                }
                return res.status(201).json({
                    success: true,
                    message: "Advertisement published successfully. 1 advertising credit used.",
                    listing: {
                        id: this.lastID,
                        image: imagePath
                    }
                });
            });
        }
    );
});
// ===============================
// MARKETPLACE — GET LISTINGS
// ===============================
app.get("/api/listings", (req, res) => {
    const sql = `
        SELECT
            listings.id,
            listings.title,
            listings.description,
            listings.category,
            listings.price,
            listings.image,
            listings.status,
            listings.created_at,
            users.username
        FROM listings
        INNER JOIN users
            ON listings.user_id = users.id
        WHERE listings.status = 'active'
        ORDER BY listings.created_at DESC
    `;
    db.all(sql, [], (err, listings) => {
        if (err) {
            console.error(
                "Listings error:",
                err
            );
            return res.status(500).json({
                success: false,
                message:
                    "Could not load advertisements."
            });
        }
        res.json({
            success: true,
            listings
        });
    });
});
// ===============================
// PRIVATE CHAT API
// ===============================
// Get users and chat previews. Mark incoming messages as delivered
// when the recipient loads the private-chat inbox.
// Chat presence: heartbeat, typing updates, and peer status.
app.post("/api/chat/presence/heartbeat", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Please log in first." });
    }
    const userId = req.session.user.id;
    db.run(
        `INSERT INTO chat_presence (user_id, last_seen)
         VALUES (?, CURRENT_TIMESTAMP)
         ON CONFLICT(user_id) DO UPDATE SET last_seen = CURRENT_TIMESTAMP`,
        [userId],
        (err) => {
            if (err) {
                console.error("Presence heartbeat error:", err.message);
                return res.status(500).json({ success: false, message: "Could not update online status." });
            }
            res.json({ success: true });
        }
    );
});
app.post("/api/chat/presence/typing", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Please log in first." });
    }
    const userId = req.session.user.id;
    const recipientId = Number(req.body.userId);
    const isTyping = Boolean(req.body.isTyping);
    if (!Number.isInteger(recipientId) || recipientId <= 0 || recipientId === userId) {
        return res.status(400).json({ success: false, message: "Invalid chat user." });
    }
    db.run(
        `INSERT INTO chat_presence (user_id, last_seen, typing_to_user_id, typing_at)
         VALUES (?, CURRENT_TIMESTAMP, ?, CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END)
         ON CONFLICT(user_id) DO UPDATE SET
             last_seen = CURRENT_TIMESTAMP,
             typing_to_user_id = CASE WHEN ? THEN ? ELSE NULL END,
             typing_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END`,
        [userId, isTyping ? recipientId : null, isTyping ? 1 : 0,
         isTyping ? 1 : 0, recipientId, isTyping ? 1 : 0],
        (err) => {
            if (err) {
                console.error("Typing update error:", err.message);
                return res.status(500).json({ success: false, message: "Could not update typing status." });
            }
            res.json({ success: true });
        }
    );
});
app.get("/api/chat/presence/:userId", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Please log in first." });
    }
    const currentUserId = req.session.user.id;
    const otherUserId = Number(req.params.userId);
    if (!Number.isInteger(otherUserId) || otherUserId <= 0 || otherUserId === currentUserId) {
        return res.status(400).json({ success: false, message: "Invalid chat user." });
    }
    db.get(
        `SELECT
             u.id,
             CASE WHEN p.last_seen >= datetime('now', '-45 seconds') THEN 1 ELSE 0 END AS is_online,
             CASE
                 WHEN p.typing_to_user_id = ?
                  AND p.typing_at >= datetime('now', '-8 seconds')
                 THEN 1 ELSE 0
             END AS is_typing
         FROM users u
         LEFT JOIN chat_presence p ON p.user_id = u.id
         WHERE u.id = ? AND u.status = 'active'`,
        [currentUserId, otherUserId],
        (err, peer) => {
            if (err) {
                console.error("Presence lookup error:", err.message);
                return res.status(500).json({ success: false, message: "Could not load chat status." });
            }
            if (!peer) {
                return res.status(404).json({ success: false, message: "Chat user not found." });
            }
            res.json({ success: true, isOnline: Boolean(peer.is_online), isTyping: Boolean(peer.is_typing) });
        }
    );
});
app.get("/api/chat/users", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in first."
        });
    }
    const currentUserId = req.session.user.id;
    db.run(
        `UPDATE messages
         SET status = 'delivered',
             delivered_at = COALESCE(delivered_at, CURRENT_TIMESTAMP)
         WHERE receiver_id = ? AND status = 'sent'`,
        [currentUserId],
        (updateErr) => {
            if (updateErr) {
                console.error("Mark delivered error:", updateErr);
                return res.status(500).json({
                    success: false,
                    message: "Could not update message delivery status."
                });
            }
            const sql = `
                SELECT
                    u.id,
                    u.username,
                    u.profile_info,
                    (
                        SELECT COUNT(*)
                        FROM messages m
                        WHERE m.sender_id = u.id
                          AND m.receiver_id = ?
                          AND m.read_at IS NULL
                    ) AS unread_count,
                    (
                        SELECT m.message
                        FROM messages m
                        WHERE (m.sender_id = u.id AND m.receiver_id = ?)
                           OR (m.sender_id = ? AND m.receiver_id = u.id)
                        ORDER BY m.created_at DESC, m.id DESC
                        LIMIT 1
                    ) AS last_message,
                    (
                        SELECT m.created_at
                        FROM messages m
                        WHERE (m.sender_id = u.id AND m.receiver_id = ?)
                           OR (m.sender_id = ? AND m.receiver_id = u.id)
                        ORDER BY m.created_at DESC, m.id DESC
                        LIMIT 1
                    ) AS last_message_at,
                    (
                        SELECT m.sender_id
                        FROM messages m
                        WHERE (m.sender_id = u.id AND m.receiver_id = ?)
                           OR (m.sender_id = ? AND m.receiver_id = u.id)
                        ORDER BY m.created_at DESC, m.id DESC
                        LIMIT 1
                    ) AS last_sender_id
                FROM users u
                WHERE u.id != ? AND u.status = 'active'
                ORDER BY
                    CASE WHEN last_message_at IS NULL THEN 1 ELSE 0 END,
                    last_message_at DESC,
                    u.username COLLATE NOCASE ASC
            `;
            db.all(
                sql,
                [
                    currentUserId,
                    currentUserId, currentUserId,
                    currentUserId, currentUserId,
                    currentUserId, currentUserId,
                    currentUserId
                ],
                (err, users) => {
                    if (err) {
                        console.error("Chat users error:", err);
                        return res.status(500).json({
                            success: false,
                            message: "Could not load chat users."
                        });
                    }
                    db.all(
                        `SELECT
                            u.id,
                            CASE
                                WHEN p.last_seen >= datetime('now', '-45 seconds')
                                THEN 1 ELSE 0
                            END AS is_online,
                            CASE
                                WHEN p.typing_to_user_id = ?
                                 AND p.typing_at >= datetime('now', '-8 seconds')
                                THEN 1 ELSE 0
                            END AS is_typing
                         FROM users u
                         LEFT JOIN chat_presence p ON p.user_id = u.id
                         WHERE u.id != ? AND u.status = 'active'`,
                        [currentUserId, currentUserId],
                        (presenceErr, presenceRows) => {
                            if (presenceErr) {
                                console.error("Contact presence error:", presenceErr);
                                return res.status(500).json({
                                    success: false,
                                    message: "Could not load contact statuses."
                                });
                            }
                            const presenceById = new Map(
                                presenceRows.map(row => [
                                    Number(row.id),
                                    {
                                        isOnline: Boolean(row.is_online),
                                        isTyping: Boolean(row.is_typing)
                                    }
                                ])
                            );
                            const contacts = users.map(user => ({
                                ...user,
                                ...(presenceById.get(Number(user.id)) || {
                                    isOnline: false,
                                    isTyping: false
                                })
                            }));
                            res.json({ success: true, users: contacts });
                        }
                    );
                }
            );
        }
    );
});
// Get private message history and mark incoming messages as read.
app.get("/api/chat/messages/:userId", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in first."
        });
    }
    const currentUserId = req.session.user.id;
    const otherUserId = Number(req.params.userId);
    if (!Number.isInteger(otherUserId) || otherUserId <= 0 ||
        otherUserId === currentUserId) {
        return res.status(400).json({
            success: false,
            message: "Invalid user."
        });
    }
    db.run(
        `UPDATE messages
         SET status = 'read',
             delivered_at = COALESCE(delivered_at, CURRENT_TIMESTAMP),
             read_at = COALESCE(read_at, CURRENT_TIMESTAMP)
         WHERE sender_id = ? AND receiver_id = ? AND read_at IS NULL`,
        [otherUserId, currentUserId],
        (updateErr) => {
            if (updateErr) {
                console.error("Mark read error:", updateErr);
                return res.status(500).json({
                    success: false,
                    message: "Could not update read status."
                });
            }
            const sql = `
                SELECT
                    messages.id,
                    messages.sender_id,
                    messages.receiver_id,
                    messages.message,
                    messages.created_at,
                    messages.status,
                    messages.delivered_at,
                    messages.read_at,
                    sender.username AS sender_username,
                    receiver.username AS receiver_username
                FROM messages
                INNER JOIN users AS sender
                    ON messages.sender_id = sender.id
                INNER JOIN users AS receiver
                    ON messages.receiver_id = receiver.id
                WHERE
                    (messages.sender_id = ? AND messages.receiver_id = ?)
                    OR
                    (messages.sender_id = ? AND messages.receiver_id = ?)
                ORDER BY messages.created_at ASC, messages.id ASC
            `;
            db.all(
                sql,
                [currentUserId, otherUserId, otherUserId, currentUserId],
                (err, messages) => {
                    if (err) {
                        console.error("Chat messages error:", err);
                        return res.status(500).json({
                            success: false,
                            message: "Could not load messages."
                        });
                    }
                    res.json({ success: true, messages });
                }
            );
        }
    );
});
// Send a private message.
app.post("/api/chat/messages", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in first."
        });
    }
    const senderId = req.session.user.id;
    const receiverId = Number(req.body.receiverId);
    const message = String(req.body.message || "").trim();
    if (!Number.isInteger(receiverId) || receiverId <= 0 ||
        receiverId === senderId) {
        return res.status(400).json({
            success: false,
            message: "Invalid receiver."
        });
    }
    if (!message) {
        return res.status(400).json({
            success: false,
            message: "Message cannot be empty."
        });
    }
    if (message.length > 2000) {
        return res.status(400).json({
            success: false,
            message: "Message is too long. Maximum 2000 characters."
        });
    }
    db.get(
        "SELECT id FROM users WHERE id = ? AND status = 'active'",
        [receiverId],
        (userErr, receiver) => {
            if (userErr) {
                console.error("Receiver lookup error:", userErr);
                return res.status(500).json({
                    success: false,
                    message: "Could not find the receiver."
                });
            }
            if (!receiver) {
                return res.status(404).json({
                    success: false,
                    message: "That user is not available for chat."
                });
            }
            db.run(
                `INSERT INTO messages (sender_id, receiver_id, message, status)
                 VALUES (?, ?, ?, 'sent')`,
                [senderId, receiverId, message],
                function (insertErr) {
                    if (insertErr) {
                        console.error("Send message error:", insertErr);
                        return res.status(500).json({
                            success: false,
                            message: "Could not send message."
                        });
                    }
                    db.get(
                        `SELECT id, sender_id, receiver_id, message, created_at,
                                status, delivered_at, read_at
                         FROM messages WHERE id = ?`,
                        [this.lastID],
                        (readErr, chatMessage) => {
                            if (readErr || !chatMessage) {
                                console.error("Read sent message error:", readErr);
                                return res.status(201).json({
                                    success: true,
                                    message: "Message sent successfully.",
                                    chatMessage: {
                                        id: this.lastID,
                                        sender_id: senderId,
                                        receiver_id: receiverId,
                                        message,
                                        status: "sent",
                                        delivered_at: null,
                                        read_at: null
                                    }
                                });
                            }
                            res.status(201).json({
                                success: true,
                                message: "Message sent successfully.",
                                chatMessage
                            });
                        }
                    );
                }
            );
        }
    );
});
// REVIEWS API
// ===============================
// Get reviews received by the currently logged-in seller
app.get("/api/reviews", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in first."
        });
    }
    const sellerId = req.session.user.id;
    const sql = `
        SELECT
            reviews.id,
            reviews.rating,
            reviews.review,
            reviews.created_at,
            reviewer.username AS reviewer_username,
            listings.title AS listing_title
        FROM reviews
        INNER JOIN users AS reviewer
            ON reviews.reviewer_id = reviewer.id
        LEFT JOIN listings
            ON reviews.listing_id = listings.id
        WHERE reviews.seller_id = ?
        ORDER BY reviews.created_at DESC, reviews.id DESC
    `;
    db.all(sql, [sellerId], (err, reviews) => {
        if (err) {
            console.error("Get reviews error:", err);
            return res.status(500).json({
                success: false,
                message: "Could not load reviews."
            });
        }
        const averageRating =
            reviews.length > 0
                ? reviews.reduce(
                    (sum, item) => sum + Number(item.rating),
                    0
                ) / reviews.length
                : 0;
        res.json({
            success: true,
            reviews,
            averageRating: Number(averageRating.toFixed(1)),
            totalReviews: reviews.length
        });
    });
});
// ===============================
// START SERVER
// ===============================
app.listen(PORT, () => {
    console.log(
        `Junior eFootball Market running on port ${PORT}`
    );
});  