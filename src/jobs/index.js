const { makeRunner } = require("./runner");

const runner = makeRunner();

function start(logFn) { return runner.start(logFn); }
function registerInterval(name, fn, everyMs) { return runner.registerInterval(name, fn, everyMs); }

module.exports = { start, registerInterval };
