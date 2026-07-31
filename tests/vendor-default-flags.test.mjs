// Ticket #32: the sandbox rows must measure the vendor's default posture, so the launcher may
// pass only flags the tool needs to start (nono's grants, srt's settings file) or that are
// output-only (--quiet/--silent). A narrowing this repo invented — a network flag, an added
// syscall filter — makes the row measure our configuration instead.
// Run: node tests/vendor-default-flags.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const script = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "run-probe-in-sandbox.sh");
const source = fs.readFileSync(script, "utf8");

// The invocation lines are the ones that actually launch the probe.
const invocations = source
  .split("\n")
  .filter((line) => !line.trimStart().startsWith("#") && line.includes('"${CMD[@]}"'));

const declared = {
  srt: ["--settings"], // minimum-to-run: srt needs a policy file to widen writes for the report
  firejail: ["--quiet"], // output-only: quiets firejail's banner, no effect on the boundary
  nono: ["--silent", "--allow-cwd", "--allow"], // output-only + minimum-to-run: nono denies all by default
};

assert.equal(invocations.length, Object.keys(declared).length, `expected one invocation per runtime, got:\n${invocations.join("\n")}`);

for (const [runtime, allowed] of Object.entries(declared)) {
  const line = invocations.find((l) => new RegExp(`^\\s*${runtime}\\b`).test(l));
  assert.ok(line, `no invocation found for ${runtime}`);
  const flags = line.match(/--[a-z0-9-]+/g) ?? [];
  assert.deepEqual([...new Set(flags)].sort(), [...allowed].sort(), `${runtime} passes undeclared flags: ${line.trim()}`);
}

console.log("ok - sandbox runtimes are launched with declared flags only");
