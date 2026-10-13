const db = require("./db");

/** Search users by name for the people picker. */
async function searchUsers(req, res) {
  const name = req.query.name || "";
  const rows = await db.query("SELECT id, name, email FROM users WHERE name LIKE '%" + name + "%' LIMIT 20");
  res.json(rows);
}

module.exports = { searchUsers };
