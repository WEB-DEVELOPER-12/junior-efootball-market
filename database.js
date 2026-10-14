
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

const dataDir = path.join(__dirname, "data");
const dbPath = path.join(dataDir, "market.db");

fs.mkdirSync(dataDir, { recursive: true });

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Database connection error:", err.message);
    } else {
        console.log("SQLite database connected.");
    }
});

db.serialize(() => {
    db.run("PRAGMA foreign_keys = ON");

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'active',
            profile_info TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS listings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            image TEXT DEFAULT '',
            collective_strength INTEGER,
            team_name TEXT DEFAULT '',
            player_count INTEGER,
            featured_player TEXT DEFAULT '',
            account_level TEXT DEFAULT '',
            platform TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'sent',
            delivered_at DATETIME DEFAULT NULL,
            read_at DATETIME DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    `);

    // Safely add chat columns to existing databases.
    db.all("PRAGMA table_info(messages)", (err, columns) => {
        if (err) {
            console.error("Could not inspect messages table:", err.message);
            return;
        }

        const existing = new Set(columns.map((column) => column.name));

        const migrations = [
            {
                name: "status",
                sql: "ALTER TABLE messages ADD COLUMN status TEXT NOT NULL DEFAULT 'sent'"
            },
            {
                name: "delivered_at",
                sql: "ALTER TABLE messages ADD COLUMN delivered_at DATETIME DEFAULT NULL"
            },
            {
                name: "read_at",
                sql: "ALTER TABLE messages ADD COLUMN read_at DATETIME DEFAULT NULL"
            }
        ];

        for (const migration of migrations) {
            if (!existing.has(migration.name)) {
                db.run(migration.sql, (migrationErr) => {
                    if (migrationErr) {
                        console.error(
                            `Migration ${migration.name} failed:`,
                            migrationErr.message
                        );
                    } else {
                        console.log(`Added messages.${migration.name}`);
                    }
                });
            }
        }
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS chat_presence (
            user_id INTEGER PRIMARY KEY,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            typing_to_user_id INTEGER DEFAULT NULL,
            typing_at DATETIME DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
                ON DELETE CASCADE
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL,
            reported_user_id INTEGER,
            listing_id INTEGER,
            reason TEXT NOT NULL,
            details TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (reporter_id) REFERENCES users(id),
            FOREIGN KEY (reported_user_id) REFERENCES users(id),
            FOREIGN KEY (listing_id) REFERENCES listings(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reviewer_id INTEGER NOT NULL,
            seller_id INTEGER NOT NULL,
            listing_id INTEGER,
            rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
            review TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (reviewer_id, seller_id, listing_id),
            FOREIGN KEY (reviewer_id) REFERENCES users(id),
            FOREIGN KEY (seller_id) REFERENCES users(id),
            FOREIGN KEY (listing_id) REFERENCES listings(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            blocker_id INTEGER NOT NULL,
            blocked_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (blocker_id, blocked_id),
            FOREIGN KEY (blocker_id) REFERENCES users(id),
            FOREIGN KEY (blocked_id) REFERENCES users(id)
        )
    `);

    console.log("Database initialization started.");
});

module.exports = db;
