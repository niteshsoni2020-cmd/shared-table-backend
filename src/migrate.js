const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const mongoose = require("mongoose");
require("dotenv").config();

function die(msg) {
  console.error("STOP:", msg);
  process.exit(1);
}

function sha256(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}

async function main() {
  const uri = String(process.env.MONGO_URI || process.env.MONGO_URL || process.env.MONGODB_URI || "").trim();
  if (!uri) die("MONGO_URI missing");

  const dir = path.join(__dirname, "migrations");
  if (!fs.existsSync(dir)) die("missing src/migrations directory");

  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".js")).sort();
  if (files.length === 0) {
    console.log("OK: no migrations to apply (empty src/migrations)");
    return;
  }

  await mongoose.connect(uri);
  const db = mongoose.connection.db;
  if (!db) die("mongo db handle unavailable after connect");

  const col = db.collection("schema_migrations");
  await col.createIndex({ id: 1 }, { unique: true });

  for (const f of files) {
    const full = path.join(dir, f);
    const code = fs.readFileSync(full, "utf8");
    const checksum = sha256(code);
    const id = f;

    const existing = await col.findOne({ id: id });

    if (existing) {
      if (String(existing.checksum || "") !== checksum) {
        die("migration checksum mismatch for " + id + " (file changed after apply)");
      }
      console.log("SKIP:", id);
      continue;
    }

    console.log("APPLY:", id);

    const mod = require(full);
    const up = mod && mod.up;
    if (typeof up !== "function") die("migration " + id + " missing export up()");

    const startedAt = new Date();
    try {
      await up(db, mongoose);
    } catch (e) {
      die("migration failed " + id + ": " + (e && e.message ? e.message : String(e)));
    }

    await col.insertOne({
      id: id,
      checksum: checksum,
      appliedAt: new Date(),
      startedAt: startedAt
    });

    console.log("DONE:", id);
  }

  console.log("OK: migrations complete");
}

main()
  .then(() => mongoose.disconnect().catch(() => {}))
  .catch((e) => die(e && e.message ? e.message : String(e)));
