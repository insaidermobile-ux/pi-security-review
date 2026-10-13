const { Pool } = require("pg");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/** Run a query. `params` are bound by the driver; `text` must not contain user input. */
async function query(text, params = []) {
  const result = await pool.query(text, params);
  return result.rows;
}

module.exports = { query };
