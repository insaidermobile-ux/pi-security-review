const crypto = require("crypto");
const db = require("./db");

/** Resolve the session token from the Authorization header into a user, or reject with 401. */
async function requireUser(req, res, next) {
  const header = req.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "unauthorized" });
  const digest = crypto.createHash("sha256").update(token).digest("hex");
  const rows = await db.query("SELECT id, name, role FROM users WHERE session_digest = $1", [digest]);
  if (rows.length === 0) return res.status(401).json({ error: "unauthorized" });
  req.user = rows[0];
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") return res.status(403).json({ error: "forbidden" });
  next();
}

module.exports = { requireUser, requireAdmin };
