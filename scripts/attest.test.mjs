// Table-driven over checked-in real-shaped documents: a resolved nono capability
// manifest and two probe reports. No nono binary, no network, no side effects.
// Run: node --test scripts/
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { attest, UNDECLARABLE } from "./attest.mjs";

const load = (name) =>
  JSON.parse(readFileSync(new URL(`../tests/fixtures/attestation/${name}.json`, import.meta.url), "utf8"));

const PROFILE = { id: "nolabs-ai/codex", version: "0.4.1" };
const result = attest({
  profile: PROFILE,
  capabilitySet: load("capability-set"),
  sandbox: load("report-under-profile"),
  baseline: load("report-baseline"),
  home: "/home/runner",
});
const byId = Object.fromEntries(result.verdicts.map((v) => [v.id, v.class]));

// One row per declared unit, one drift class each.
const EXPECTED = {
  // observed reachable under the profile (a directory grant covering the file seen)
  "filesystem.read:~/.ssh": "match",
  // not observed, but the baseline could reach it — the profile overclaims
  "filesystem.read:~/.aws/credentials": "overclaim",
  // not observed and not in the baseline either — nothing was there to reach
  "filesystem.read:~/.kube/config": "unprovable",
  // a readwrite grant is two declarations, and they can land differently
  "filesystem.read:/tmp/workspace": "unprovable",
  "filesystem.write:/tmp/workspace": "match",
  // declared, nothing here observes the category
  "network.mode": "unattested",
  "network.allow_domains": "unattested",
  "network.ports": "unattested",
  "network.endpoints": "unattested",
  "credentials:openai": "unattested",
  "process.process_info_mode": "unattested",
  "process.signal_mode": "unattested",
  "process.ipc_mode": "unattested",
  "resources.max_processes": "unattested",
};

for (const [id, cls] of Object.entries(EXPECTED)) {
  test(`${id} -> ${cls}`, () => assert.equal(byId[id], cls));
}

test("every declared unit gets exactly one verdict and nothing else does", () => {
  assert.deepEqual(Object.keys(byId).sort(), Object.keys(EXPECTED).sort());
  assert.equal(result.verdicts.length, Object.keys(EXPECTED).length);
});

test("unattested is never folded into match and carries why", () => {
  for (const v of result.verdicts.filter((x) => x.class === "unattested")) {
    assert.ok(v.reason, `${v.id} must say why nothing observes it`);
  }
});

test("reachable-but-undeclared is a gap, kept distinct from the declared-side verdicts", () => {
  assert.deepEqual(result.gaps, [
    { class: "gap", findingType: "sensitive_readable_paths", path: "/etc/passwd" },
    { class: "gap", findingType: "writeable_paths", path: "/var/tmp" },
  ]);
  assert.ok(!result.verdicts.some((v) => v.class === "gap"));
});

test("mount topology, hostname and user context are excluded, never gaps", () => {
  assert.deepEqual(result.excluded, [
    "mounted_volumes_detections",
    "hostname_detection",
    "user_context_detection",
  ]);
  for (const ft of UNDECLARABLE) {
    assert.ok(!result.gaps.some((g) => g.findingType === ft));
    assert.ok(!result.verdicts.some((v) => v.findingType === ft));
  }
});

test("coverage states the attested fraction of the declared surface", () => {
  assert.deepEqual(result.coverage, {
    declared: 14,
    attested: 5,
    unattested: 9,
    attestedFraction: 5 / 14,
  });
});

test("the attestation names the profile and the manifest it checked", () => {
  assert.deepEqual(result.profile, { id: "nolabs-ai/codex", version: "0.4.1", manifestVersion: "0.1.0" });
});

test("a verdict that cannot name its claim is refused", () => {
  assert.throws(
    () => attest({ profile: { id: "nolabs-ai/codex" }, capabilitySet: load("capability-set"), sandbox: {}, baseline: {} }),
    /profile\.id and profile\.version are required/,
  );
});
