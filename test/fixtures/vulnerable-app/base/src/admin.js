const fs = require("fs");
const path = require("path");

const SETTINGS_FILE = path.resolve(__dirname, "..", "settings.json");

/** Administrators can replace the server settings, including the outbound webhook URL. */
function updateSettings(req, res) {
  const settings = req.body;
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
  res.json({ ok: true });
}

module.exports = { updateSettings };
