const path = require("path");
const fs = require("fs");

const UPLOAD_ROOT = path.resolve(__dirname, "..", "uploads");

/** Stream a file from the uploads directory. */
function download(req, res) {
  const requested = String(req.query.name || "");
  const target = path.resolve(UPLOAD_ROOT, requested);
  if (target !== UPLOAD_ROOT && !target.startsWith(UPLOAD_ROOT + path.sep)) {
    return res.status(400).json({ error: "invalid file name" });
  }
  if (!fs.existsSync(target)) return res.status(404).end();
  fs.createReadStream(target).pipe(res);
}

module.exports = { download };
