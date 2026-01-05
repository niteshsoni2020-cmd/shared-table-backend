"use strict";

// Minimal smoke: validate server.js parses + can be required without crashing.
// NOTE: If server.js starts listening on import, this will fail and we will switch to a pure syntax-only harness.
try {
  require("../server.js");
  console.log("SMOKE_OK: require(server.js)");
  process.exit(0);
} catch (e) {
  console.error("SMOKE_FAIL:", (e && e.message) ? e.message : String(e));
  process.exit(1);
}
