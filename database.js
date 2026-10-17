
require("dotenv").config();

const usePostgres =
  process.env.DATABASE_URL &&
  (process.env.NODE_ENV === "production" ||
    process.env.USE_POSTGRES === "true");

if (usePostgres) {
  console.log("Using Neon PostgreSQL database.");
  module.exports = require("./database-postgres");
} else {
  console.log("Using local SQLite database.");
  module.exports = require("./database-sqlite");
}
