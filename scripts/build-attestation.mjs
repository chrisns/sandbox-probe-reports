// Produces site/attestation.json — the document the attestation view renders.
// The diff is a pure function over checked-in documents (scripts/attest.mjs), so
// the published verdict is reviewable without nono, without a probe release and
// without running a scan: exactly the point of publishing it this way.
//
// Until a real profiled run lands, the inputs are the checked-in fixtures. The
// `source` field says so on the document itself, so nothing published here can
// be mistaken for an observed run.
//
// Regenerate: node scripts/build-attestation.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { attest } from "./attest.mjs";

const OUT = new URL("../site/attestation.json", import.meta.url);
const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`../tests/fixtures/attestation/${name}.json`, import.meta.url), "utf8"));

export function buildAttestation() {
  return {
    source: "tests/fixtures/attestation — checked-in documents, not an observed run",
    ...attest({
      profile: { id: "nolabs-ai/codex", version: "0.4.1" },
      capabilitySet: fixture("capability-set"),
      sandbox: fixture("report-under-profile"),
      baseline: fixture("report-baseline"),
      home: "/home/runner",
    }),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  writeFileSync(OUT, JSON.stringify(buildAttestation(), null, 2) + "\n");
  console.error(`build-attestation: wrote ${fileURLToPath(OUT)}`);
}
