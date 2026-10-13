const express = require("express");
const { requireUser, requireAdmin } = require("./auth");
const files = require("./files");
const admin = require("./admin");
const users = require("./users");

const app = express();
app.use(express.json());

app.get("/files", requireUser, files.download);
app.put("/admin/settings", requireUser, requireAdmin, admin.updateSettings);
app.get("/users/search", users.searchUsers);

app.listen(process.env.PORT || 3000);
