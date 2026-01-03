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
  const required = extractVars(str);
  for (const key of required) {
    if (!(key in vars)) {
      throw new Error("TEMPLATE_VAR_MISSING_" + key);
    }
    if (String(vars[key]).trim().length === 0) {
      throw new Error("TEMPLATE_VAR_EMPTY_" + key);
    }
  }
  return str.replace(/\{\{([A-Za-z0-9_]+)\}\}/g, (_, k) => String(vars[k]));
}

function loadTemplateById(id) {
  if (!id) throw new Error("TEMPLATE_ID_REQUIRED");
  const file = path.join(process.cwd(), "emails", id);
  if (!fs.existsSync(file)) {
    throw new Error("TEMPLATE_FILE_NOT_FOUND_" + id);
  }
  return parseTemplate(fs.readFileSync(file, "utf-8"));
}

function renderTemplate(id, vars) {
  const t = loadTemplateById(id);
  return {
    subject: renderVars(t.subject, vars),
    body: renderVars(t.body, vars)
  };
}

module.exports = { renderTemplate };
