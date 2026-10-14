const express = require("express");
const db = require("./database");

const router = express.Router();

/* ===============================
   ADMIN AUTHENTICATION
================================ */

function requireAdmin(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({
            success: false,
            message: "You must be logged in."
        });
    }

    if (req.session.user.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Admin access required."
        });
    }

    next();
}

/* ===============================
   ADMIN TABLES
================================ */

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER,
            reported_user_id INTEGER,
            listing_id INTEGER,
            reason TEXT NOT NULL,
            details TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS admin_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id INTEGER,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'general',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    `);
});

/* ===============================
   ADMIN STATS
================================ */

router.get("/stats", requireAdmin, (req, res) => {
    const stats = {};

    db.get("SELECT COUNT(*) AS count FROM users", [], (err, users) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: "Could not load user statistics."
            });
        }

        stats.users = users.count;

        db.get(
            "SELECT COUNT(*) AS count FROM users WHERE status = 'active'",
            [],
            (err, activeUsers) => {
                if (err) {
                    return res.status(500).json({
                        success: false,
                        message: "Could not load active user statistics."
                    });
                }

                stats.activeUsers = activeUsers.count;

                db.get(
                    "SELECT COUNT(*) AS count FROM listings",
                    [],
                    (err, listings) => {
                        if (err) {
                            return res.status(500).json({
                                success: false,
                                message: "Could not load listing statistics."
                            });
                        }

                        stats.listings = listings.count;

                        db.get(
                            "SELECT COUNT(*) AS count FROM listings WHERE status = 'active'",
                            [],
                            (err, activeListings) => {
                                if (err) {
                                    return res.status(500).json({
                                        success: false,
                                        message: "Could not load active listing statistics."
                                    });
                                }

                                stats.activeListings = activeListings.count;

                                db.get(
                                    "SELECT COUNT(*) AS count FROM reports WHERE status = 'pending'",
                                    [],
                                    (err, pendingReports) => {
                                        if (err) {
                                            return res.status(500).json({
                                                success: false,
                                                message: "Could not load report statistics."
                                            });
                                        }

                                        stats.pendingReports =
                                            pendingReports.count;

                                        db.get(
                                            "SELECT COUNT(*) AS count FROM users WHERE role = 'admin'",
                                            [],
                                            (err, admins) => {
                                                stats.admins = err
                                                    ? 0
                                                    : admins.count;

                                                db.get(
                                                    "SELECT COUNT(*) AS count FROM announcements WHERE is_active = 1",
                                                    [],
                                                    (err, announcements) => {
                                                        stats.announcements =
                                                            err
                                                                ? 0
                                                                : announcements.count;

                                                        res.json({
                                                            success: true,
                                                            stats
                                                        });
                                                    }
                                                );
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );
    });
});

/* ===============================
   ADMIN PROFILE
================================ */

router.get("/me", requireAdmin, (req, res) => {
    db.get(
        `
        SELECT id, username, email, role, status, created_at
        FROM users
        WHERE id = ?
        `,
        [req.session.user.id],
        (err, admin) => {
            if (err || !admin) {
                return res.status(500).json({
                    success: false,
                    message: "Could not load admin profile."
                });
            }

            res.json({
                success: true,
                admin
            });
        }
    );
});

/* ===============================
   USERS
================================ */

router.get("/users", requireAdmin, (req, res) => {
    db.all(
        `
        SELECT id, username, email, role, status, created_at
        FROM users
        ORDER BY created_at DESC
        `,
        [],
        (err, users) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not load users."
                });
            }

            res.json({
                success: true,
                users
            });
        }
    );
});

router.patch("/users/:id/status", requireAdmin, (req, res) => {
    const userId = Number(req.params.id);
    const { status } = req.body;

    const allowedStatuses = [
        "active",
        "suspended",
        "banned"
    ];

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
            success: false,
            message: "Invalid user status."
        });
    }

    if (userId === req.session.user.id) {
        return res.status(400).json({
            success: false,
            message: "You cannot change your own admin status here."
        });
    }

    db.get(
        "SELECT role FROM users WHERE id = ?",
        [userId],
        (err, user) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not check user."
                });
            }

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: "User not found."
                });
            }

            if (user.role === "admin") {
                return res.status(403).json({
                    success: false,
                    message: "Admin accounts are protected."
                });
            }

            db.run(
                "UPDATE users SET status = ? WHERE id = ?",
                [status, userId],
                function (updateErr) {
                    if (updateErr) {
                        return res.status(500).json({
                            success: false,
                            message: "Could not update user status."
                        });
                    }

                    db.run(
                        `
                        INSERT INTO admin_actions
                        (admin_id, action, target_type, target_id, details)
                        VALUES (?, ?, ?, ?, ?)
                        `,
                        [
                            req.session.user.id,
                            "change_user_status",
                            "user",
                            userId,
                            `Changed user status to ${status}`
                        ]
                    );

                    res.json({
                        success: true,
                        message: `User status changed to ${status}.`
                    });
                }
            );
        }
    );
});

/* ===============================
   LISTINGS
================================ */

router.get("/listings", requireAdmin, (req, res) => {
    db.all(
        `
        SELECT
            listings.id,
            listings.title,
            listings.description,
            listings.category,
            listings.price,
            listings.status,
            listings.created_at,
            users.username
        FROM listings
        LEFT JOIN users ON users.id = listings.user_id
        ORDER BY listings.created_at DESC
        `,
        [],
        (err, listings) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not load listings."
                });
            }

            res.json({
                success: true,
                listings
            });
        }
    );
});

router.patch("/listings/:id/status", requireAdmin, (req, res) => {
    const listingId = Number(req.params.id);
    const { status } = req.body;

    const allowedStatuses = [
        "active",
        "pending",
        "inactive"
    ];

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
            success: false,
            message: "Invalid listing status."
        });
    }

    db.run(
        "UPDATE listings SET status = ? WHERE id = ?",
        [status, listingId],
        function (err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not update listing."
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Listing not found."
                });
            }

            db.run(
                `
                INSERT INTO admin_actions
                (admin_id, action, target_type, target_id, details)
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    req.session.user.id,
                    "change_listing_status",
                    "listing",
                    listingId,
                    `Changed listing status to ${status}`
                ]
            );

            res.json({
                success: true,
                message: `Listing marked as ${status}.`
            });
        }
    );
});

router.delete("/listings/:id", requireAdmin, (req, res) => {
    const listingId = Number(req.params.id);

    db.run(
        "DELETE FROM listings WHERE id = ?",
        [listingId],
        function (err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not delete listing."
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Listing not found."
                });
            }

            db.run(
                `
                INSERT INTO admin_actions
                (admin_id, action, target_type, target_id, details)
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    req.session.user.id,
                    "delete_listing",
                    "listing",
                    listingId,
                    "Deleted marketplace listing"
                ]
            );

            res.json({
                success: true,
                message: "Listing deleted successfully."
            });
        }
    );
});

/* ===============================
   REPORTS
================================ */

router.get("/reports", requireAdmin, (req, res) => {
    db.all(
        `
        SELECT
            reports.id,
            reports.reason,
            reports.details,
            reports.status,
            reports.listing_id,
            reports.created_at,
            reporter.username AS reporter_username,
            reported.username AS reported_username
        FROM reports
        LEFT JOIN users reporter
            ON reporter.id = reports.reporter_id
        LEFT JOIN users reported
            ON reported.id = reports.reported_user_id
        ORDER BY reports.created_at DESC
        `,
        [],
        (err, reports) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not load reports."
                });
            }

            res.json({
                success: true,
                reports
            });
        }
    );
});

router.patch("/reports/:id/status", requireAdmin, (req, res) => {
    const reportId = Number(req.params.id);
    const { status } = req.body;

    const allowedStatuses = [
        "pending",
        "reviewed",
        "resolved",
        "dismissed"
    ];

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
            success: false,
            message: "Invalid report status."
        });
    }

    db.run(
        "UPDATE reports SET status = ? WHERE id = ?",
        [status, reportId],
        function (err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not update report."
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Report not found."
                });
            }

            db.run(
                `
                INSERT INTO admin_actions
                (admin_id, action, target_type, target_id, details)
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    req.session.user.id,
                    "change_report_status",
                    "report",
                    reportId,
                    `Changed report status to ${status}`
                ]
            );

            res.json({
                success: true,
                message: `Report marked as ${status}.`
            });
        }
    );
});

/* ===============================
   ANNOUNCEMENTS
================================ */

/* Get announcements for admin */

router.get("/announcements", requireAdmin, (req, res) => {
    db.all(
        `
        SELECT
            announcements.id,
            announcements.title,
            announcements.message,
            announcements.type,
            announcements.is_active,
            announcements.created_at,
            announcements.updated_at,
            users.username AS created_by_username
        FROM announcements
        LEFT JOIN users
            ON users.id = announcements.created_by
        ORDER BY announcements.created_at DESC
        `,
        [],
        (err, announcements) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not load announcements."
                });
            }

            res.json({
                success: true,
                announcements
            });
        }
    );
});

/* Create announcement */

router.post("/announcements", requireAdmin, (req, res) => {
    const title = String(req.body.title || "").trim();
    const message = String(req.body.message || "").trim();
    const type = String(req.body.type || "general").trim();

    const allowedTypes = [
        "general",
        "important",
        "update",
        "warning",
        "maintenance"
    ];

    if (!title || !message) {
        return res.status(400).json({
            success: false,
            message: "Title and message are required."
        });
    }

    if (!allowedTypes.includes(type)) {
        return res.status(400).json({
            success: false,
            message: "Invalid announcement type."
        });
    }

    db.run(
        `
        INSERT INTO announcements
        (title, message, type, is_active, created_by)
        VALUES (?, ?, ?, 1, ?)
        `,
        [
            title,
            message,
            type,
            req.session.user.id
        ],
        function (err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not create announcement."
                });
            }

            const announcementId = this.lastID;

            db.run(
                `
                INSERT INTO admin_actions
                (admin_id, action, target_type, target_id, details)
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    req.session.user.id,
                    "create_announcement",
                    "announcement",
                    announcementId,
                    `Created announcement: ${title}`
                ]
            );

            res.status(201).json({
                success: true,
                message: "Announcement created successfully.",
                id: announcementId
            });
        }
    );
});

/* Update announcement */

router.put("/announcements/:id", requireAdmin, (req, res) => {
    const announcementId = Number(req.params.id);

    const title = String(req.body.title || "").trim();
    const message = String(req.body.message || "").trim();
    const type = String(req.body.type || "general").trim();

    const allowedTypes = [
        "general",
        "important",
        "update",
        "warning",
        "maintenance"
    ];

    if (!title || !message) {
        return res.status(400).json({
            success: false,
            message: "Title and message are required."
        });
    }

    if (!allowedTypes.includes(type)) {
        return res.status(400).json({
            success: false,
            message: "Invalid announcement type."
        });
    }

    db.run(
        `
        UPDATE announcements
        SET
            title = ?,
            message = ?,
            type = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `,
        [
            title,
            message,
            type,
            announcementId
        ],
        function (err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not update announcement."
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Announcement not found."
                });
            }

            db.run(
                `
                INSERT INTO admin_actions
                (admin_id, action, target_type, target_id, details)
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    req.session.user.id,
                    "update_announcement",
                    "announcement",
                    announcementId,
                    `Updated announcement: ${title}`
                ]
            );

            res.json({
                success: true,
                message: "Announcement updated successfully."
            });
        }
    );
});

/* Activate / deactivate announcement */

router.patch("/announcements/:id/status", requireAdmin, (req, res) => {
    const announcementId = Number(req.params.id);
    const isActive = Number(req.body.is_active);

    if (![0, 1].includes(isActive)) {
        return res.status(400).json({
            success: false,
            message: "Invalid announcement status."
        });
    }

    db.run(
        `
        UPDATE announcements
        SET
            is_active = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `,
        [
            isActive,
            announcementId
        ],
        function (err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not update announcement status."
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Announcement not found."
                });
            }

            db.run(
                `
                INSERT INTO admin_actions
                (admin_id, action, target_type, target_id, details)
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    req.session.user.id,
                    "change_announcement_status",
                    "announcement",
                    announcementId,
                    isActive
                        ? "Activated announcement"
                        : "Deactivated announcement"
                ]
            );

            res.json({
                success: true,
                message: isActive
                    ? "Announcement activated."
                    : "Announcement deactivated."
            });
        }
    );
});

/* Delete announcement */

router.delete("/announcements/:id", requireAdmin, (req, res) => {
    const announcementId = Number(req.params.id);

    db.run(
        "DELETE FROM announcements WHERE id = ?",
        [announcementId],
        function (err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not delete announcement."
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Announcement not found."
                });
            }

            db.run(
                `
                INSERT INTO admin_actions
                (admin_id, action, target_type, target_id, details)
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    req.session.user.id,
                    "delete_announcement",
                    "announcement",
                    announcementId,
                    "Deleted announcement"
                ]
            );

            res.json({
                success: true,
                message: "Announcement deleted successfully."
            });
        }
    );
});

/* ===============================
   PUBLIC ANNOUNCEMENTS
================================ */

router.get("/public-announcements", (req, res) => {
    db.all(
        `
        SELECT
            id,
            title,
            message,
            type,
            created_at
        FROM announcements
        WHERE is_active = 1
        ORDER BY created_at DESC
        `,
        [],
        (err, announcements) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not load announcements."
                });
            }

            res.json({
                success: true,
                announcements
            });
        }
    );
});

/* ===============================
   ADVERTISING PAYMENTS
================================ */

// Get advertising payment submissions
router.get("/advertising-payments", requireAdmin, (req, res) => {
    db.all(
        `
        SELECT
            advertising_payments.id,
            advertising_payments.user_id,
            users.username,
            users.email,
            advertising_packages.name AS package_name,
            advertising_packages.credits,
            advertising_payments.amount,
            advertising_payments.transaction_code,
            advertising_payments.status,
            advertising_payments.full_name,
            advertising_payments.whatsapp_number,
            advertising_payments.email,
            advertising_payments.screenshot,
            advertising_payments.reviewed_by,
            advertising_payments.reviewed_at,
            advertising_payments.created_at
        FROM advertising_payments
        JOIN users
            ON users.id = advertising_payments.user_id
        JOIN advertising_packages
            ON advertising_packages.id = advertising_payments.package_id
        ORDER BY
            CASE
                WHEN advertising_payments.status = 'pending' THEN 0
                ELSE 1
            END,
            advertising_payments.created_at DESC
        `,
        [],
        (err, payments) => {
            if (err) {
                console.error(
                    "Advertising payments error:",
                    err
                );

                return res.status(500).json({
                    success: false,
                    message: "Could not load advertising payments."
                });
            }

            console.log(
                "ADVERTISING PAYMENTS API:",
                JSON.stringify(payments, null, 2)
            );

            res.json({
                success: true,
                payments
            });
        }
    );
});

// Approve an advertising payment and add credits
router.patch(
    "/advertising-payments/:id/approve",
    requireAdmin,
    (req, res) => {
        const paymentId = Number(req.params.id);

        if (!Number.isInteger(paymentId) || paymentId <= 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid payment ID."
            });
        }

        db.get(
            `
            SELECT
                advertising_payments.id,
                advertising_payments.user_id,
                advertising_payments.status,
                advertising_packages.credits,
                advertising_packages.name AS package_name
            FROM advertising_payments
            JOIN advertising_packages
                ON advertising_packages.id =
                   advertising_payments.package_id
            WHERE advertising_payments.id = ?
            `,
            [paymentId],
            (findErr, payment) => {
                if (findErr) {
                    console.error(
                        "Find advertising payment error:",
                        findErr
                    );

                    return res.status(500).json({
                        success: false,
                        message: "Could not find the payment."
                    });
                }

                if (!payment) {
                    return res.status(404).json({
                        success: false,
                        message: "Payment not found."
                    });
                }

                if (payment.status !== "pending") {
                    return res.status(400).json({
                        success: false,
                        message:
                            "This payment has already been reviewed."
                    });
                }

                db.serialize(() => {
                    db.run(
                        `
                        UPDATE advertising_payments
                        SET
                            status = 'approved',
                            reviewed_by = ?,
                            reviewed_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                          AND status = 'pending'
                        `,
                        [req.session.user.id, paymentId],
                        function (updateErr) {
                            if (updateErr) {
                                console.error(
                                    "Approve payment error:",
                                    updateErr
                                );

                                return res.status(500).json({
                                    success: false,
                                    message:
                                        "Could not approve the payment."
                                });
                            }

                            if (this.changes === 0) {
                                return res.status(400).json({
                                    success: false,
                                    message:
                                        "This payment has already been reviewed."
                                });
                            }

                            db.run(
                                `
                                INSERT INTO advertising_credits
                                (user_id, credits, updated_at)
                                VALUES (?, ?, CURRENT_TIMESTAMP)
                                ON CONFLICT(user_id)
                                DO UPDATE SET
                                    credits =
                                        advertising_credits.credits + excluded.credits,
                                    updated_at = CURRENT_TIMESTAMP
                                `,
                                [
                                    payment.user_id,
                                    payment.credits
                                ],
                                (creditErr) => {
                                    if (creditErr) {
                                        console.error(
                                            "Add advertising credits error:",
                                            creditErr
                                        );

                                        return res.status(500).json({
                                            success: false,
                                            message:
                                                "Payment approved, but credits could not be added automatically. Please check the user's credit balance."
                                        });
                                    }

                                    db.run(
                                        `
                                        INSERT INTO admin_actions
                                        (
                                            admin_id,
                                            action,
                                            target_type,
                                            target_id,
                                            details
                                        )
                                        VALUES (?, ?, ?, ?, ?)
                                        `,
                                        [
                                            req.session.user.id,
                                            "approve_advertising_payment",
                                            "advertising_payment",
                                            paymentId,
                                            `Approved ${payment.package_name} package and added ${payment.credits} advertising credit(s) to user ${payment.user_id}`
                                        ]
                                    );

                                    res.json({
                                        success: true,
                                        message:
                                            `Payment approved. ${payment.credits} advertising credit(s) added.`,
                                        creditsAdded:
                                            payment.credits
                                    });
                                }
                            );
                        }
                    );
                });
            }
        );
    }
);

// Reject an advertising payment
router.patch(
    "/advertising-payments/:id/reject",
    requireAdmin,
    (req, res) => {
        const paymentId = Number(req.params.id);

        if (!Number.isInteger(paymentId) || paymentId <= 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid payment ID."
            });
        }

        db.run(
            `
            UPDATE advertising_payments
            SET
                status = 'rejected',
                reviewed_by = ?,
                reviewed_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND status = 'pending'
            `,
            [req.session.user.id, paymentId],
            function (err) {
                if (err) {
                    console.error(
                        "Reject advertising payment error:",
                        err
                    );

                    return res.status(500).json({
                        success: false,
                        message: "Could not reject the payment."
                    });
                }

                if (this.changes === 0) {
                    return res.status(404).json({
                        success: false,
                        message:
                            "Payment not found or it has already been reviewed."
                    });
                }

                db.run(
                    `
                    INSERT INTO admin_actions
                    (
                        admin_id,
                        action,
                        target_type,
                        target_id,
                        details
                    )
                    VALUES (?, ?, ?, ?, ?)
                    `,
                    [
                        req.session.user.id,
                        "reject_advertising_payment",
                        "advertising_payment",
                        paymentId,
                        "Rejected advertising payment"
                    ]
                );

                res.json({
                    success: true,
                    message: "Payment rejected successfully."
                });
            }
        );
    }
);

/* ===============================
   EXPORT
================================ */

module.exports = router;
