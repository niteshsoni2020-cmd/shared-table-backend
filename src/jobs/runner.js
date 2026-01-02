function makeRunner() {
  const state = { started: false, log: null, intervals: {} };

  function setLogger(fn) { state.log = fn; }

  function log(level, msg, meta) {
    const l = state.log;
    if (l) {
      try { l(level, msg, meta || {}); } catch (_) {}
      return;
    }
    try { console.log(String(level || "info"), String(msg || ""), meta || {}); } catch (_) {}
  }

  function start(logger) {
    if (state.started === true) return;
    if (logger) setLogger(logger);
    state.started = true;
    log("info", "job_runner_started", {});
  }

  function toInt(v) {
    try { return Number(v) | 0; } catch (_) { return 0; }
  }

  function registerInterval(name, fn, everyMs) {
    const jobName = String(name || "").trim();
    const ms = toInt(everyMs);

    if (jobName.length === 0) throw new Error("JOB_NAME_REQUIRED");
    if (ms < 1000) throw new Error("JOB_INTERVAL_TOO_SMALL");
    if (typeof fn !== "function") throw new Error("JOB_FN_REQUIRED");

    if (state.intervals[jobName]) return;

    const handle = setInterval(async () => {
      const startedAt = new Date();
      try {
        log("info", "job_start", { job: jobName, startedAt: startedAt.toISOString() });
        await Promise.resolve(fn());
        const endedAt = new Date();
        log("info", "job_ok", { job: jobName, startedAt: startedAt.toISOString(), endedAt: endedAt.toISOString() });
      } catch (err) {
        const endedAt = new Date();
        const msg = err ? String(err.message || err) : "unknown";
        log("error", "job_fail", { job: jobName, startedAt: startedAt.toISOString(), endedAt: endedAt.toISOString(), error: msg });
      }
    }, ms);

    state.intervals[jobName] = { handle, everyMs: ms };
    log("info", "job_registered_interval", { job: jobName, everyMs: ms });
  }

  return { start, registerInterval };
}

module.exports = { makeRunner };
