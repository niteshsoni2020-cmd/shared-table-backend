const fs = require("fs");
const path = require("path");

function parseTemplate(raw) {
  const text = String(raw || "");
  const lines = text.split(/\r?\n/);

  const first = String(lines[0] || "").trim();
  if (first.slice(0, 8) !== "Subject:") {
    throw new Error("TEMPLATE_SUBJECT_MISSING");
  }

  const subject = first.slice(8).trim();
  if (subject.length === 0) {
    throw new Error("TEMPLATE_SUBJECT_EMPTY");
  }

  const body = lines.slice(1).join("\n").replace(/^\s*\n/, "");
  if (body.trim().length === 0) {
    throw new Error("TEMPLATE_BODY_EMPTY");
  }

  return { subject, body };
}

function extractVars(str) {
  const out = new Set();
  const re = /\{\{([A-Za-z0-9_]+)\}\}/g;
  let m;
  while ((m = re.exec(str)) !== null) {
    out.add(m[1]);
  }
  return Array.from(out);
}

function renderVars(str, vars) {
  const v = (vars && typeof vars === "object") ? vars : {};
  return str.replace(/\{\{([A-Za-z0-9_]+)\}\}/g, (_, k) => {
    const raw = Object.prototype.hasOwnProperty.call(v, k) ? v[k] : "";
    const s = String(raw == null ? "" : raw).trim();
    return (s.length > 0) ? s : "—";
  });
}


function loadTemplateById(id) {
  if (!id) throw new Error("TEMPLATE_ID_REQUIRED");
  const raw = String(id);
  const base = raw.endsWith(".txt") ? raw.slice(0, -4) : raw;
  const file = path.join(process.cwd(), "emails", base + ".txt");
  if (!fs.existsSync(file)) {
    throw new Error("TEMPLATE_FILE_NOT_FOUND_" + base + ".txt");
  }
  return parseTemplate(fs.readFileSync(file, "utf-8"));
}

function requiredVarsForTemplateId(id) {
  const t = loadTemplateById(id);
  const combined = String(t.subject || "") + "\n" + String(t.body || "");
  return extractVars(combined);
}

function renderTemplate(id, vars) {
  const t = loadTemplateById(id);
  return {
    subject: renderVars(t.subject, vars),
    body: renderVars(t.body, vars)
  };
}

module.exports = { renderTemplate, requiredVarsForTemplateId };
