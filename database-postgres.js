
const { Pool, types } = require("pg");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required for PostgreSQL mode.");
}

// Application IDs are small integers, so return PostgreSQL BIGINT values
// as JavaScript numbers for compatibility with the existing application.
types.setTypeParser(20, (value) => Number(value));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  connectionTimeoutMillis: 15000,
  idleTimeoutMillis: 30000
});

pool.on("error", (err) => {
  console.error("PostgreSQL pool error:", err.message);
});

function translateSql(sql) {
  let query = sql.trim();

  // These tables already exist in Neon. Ignore SQLite startup DDL.
  if (/^CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS/i.test(query)) {
    return null;
  }

  query = query
    .replace(
      /datetime\(\s*'now'\s*,\s*'-(\d+)\s+seconds'\s*\)/gi,
      "(CURRENT_TIMESTAMP - INTERVAL '$1 seconds')"
    )
    .replace(/datetime\(\s*'now'\s*\)/gi, "CURRENT_TIMESTAMP")
    .replace(
      /(\b[a-zA-Z_][\w]*\.)?username\s+COLLATE\s+NOCASE/gi,
      (_, prefix) => `LOWER(${prefix || ""}username)`
    );

  // Convert SQLite ? placeholders into PostgreSQL $1, $2, etc.
  let index = 0;
  query = query.replace(/\?/g, () => `$${++index}`);

  return query;
}

function normalizeArgs(params, callback) {
  if (typeof params === "function") {
    return { params: [], callback: params };
  }

  return {
    params: Array.isArray(params) ? params : [],
    callback: typeof callback === "function" ? callback : null
  };
}

function get(sql, params, callback) {
  const args = normalizeArgs(params, callback);
  const query = translateSql(sql);

  if (query === null) {
    if (args.callback) args.callback(null, undefined);
    return;
  }

  pool.query(query, args.params)
    .then((result) => {
      if (args.callback) {
        args.callback(null, result.rows[0]);
      }
    })
    .catch((err) => {
      if (args.callback) {
        args.callback(err);
      } else {
        console.error("Database get error:", err.message);
      }
    });
}

function all(sql, params, callback) {
  const args = normalizeArgs(params, callback);
  const query = translateSql(sql);

  if (query === null) {
    if (args.callback) args.callback(null, []);
    return;
  }

  pool.query(query, args.params)
    .then((result) => {
      if (args.callback) {
        args.callback(null, result.rows);
      }
    })
    .catch((err) => {
      if (args.callback) {
        args.callback(err);
      } else {
        console.error("Database all error:", err.message);
      }
    });
}

function run(sql, params, callback) {
  const args = normalizeArgs(params, callback);
  let query = translateSql(sql);

  if (query === null) {
    if (args.callback) {
      args.callback.call(
        { lastID: undefined, changes: 0 },
        null
      );
    }
    return this;
  }

  const isInsert = /^\s*INSERT\s+INTO\s+/i.test(query);
  const isPresenceInsert =
    /^\s*INSERT\s+INTO\s+chat_presence\b/i.test(query);

  // Most inserted records have an id column. chat_presence uses user_id.
  if (
    isInsert &&
    !isPresenceInsert &&
    !/\bRETURNING\b/i.test(query)
  ) {
    query = query.replace(/;$/, "") + " RETURNING id";
  }

  pool.query(query, args.params)
    .then((result) => {
      const id = result.rows?.[0]?.id;

      const context = {
        lastID: id == null ? undefined : Number(id),
        changes: result.rowCount || 0
      };

      if (args.callback) {
        args.callback.call(context, null);
      }
    })
    .catch((err) => {
      if (args.callback) {
        args.callback.call(
          { lastID: undefined, changes: 0 },
          err
        );
      } else {
        console.error("Database run error:", err.message);
      }
    });

  return this;
}

function serialize(callback) {
  if (typeof callback === "function") {
    callback();
  }
}

module.exports = {
  get,
  all,
  run,
  serialize,
  pool,
  close: () => pool.end()
};

console.log("PostgreSQL database adapter loaded.");
