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
const INPUT = {
  profile: PROFILE,
  capabilitySet: load("capability-set"),
  sandbox: load("report-under-profile"),
  baseline: load("report-baseline"),
  home: "/home/runner",
};
const result = attest(INPUT);
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
  // reached under the profile
  "network.allow_domains:api.openai.com": "match",
  // not reached under the profile, but the baseline reached raw.githubusercontent.com
  // through the same suffix wildcard — the profile advertises what it does not deliver
  "network.allow_domains:.githubusercontent.com": "overclaim",
  // neither side reached it: nothing to prove either way
  "network.allow_domains:registry.npmjs.org": "unprovable",
  // declared open, observed open
  "network.ports.localhost:8080": "match",
  // declared, closed under the profile, open in the baseline
  "network.ports.listen:9229": "overclaim",
  // declared, nothing here observes the category
  "network.mode": "unattested",
  "network.endpoints:api.github.com:443": "unattested",
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
    // egress to a destination nothing declares; api.openai.com is declared as a
    // domain and api.github.com by an endpoint, so neither is a gap
    { class: "gap", findingType: "external_host_connectivity", host: "telemetry.example.net" },
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
    declared: 17,
    attested: 10,
    unattested: 7,
    attestedFraction: 10 / 17,
  });
});

test("coverage arithmetic counts network grants, so it moves when they do", () => {
  const cs = load("capability-set");
  cs.network.allow_domains = cs.network.allow_domains.slice(0, 1);
  cs.network.ports = { localhost: [8080] };
  const fewer = attest({ ...INPUT, capabilitySet: cs }).coverage;
  assert.deepEqual(fewer, { declared: 14, attested: 7, unattested: 7, attestedFraction: 7 / 14 });
  assert.notEqual(fewer.attestedFraction, result.coverage.attestedFraction);
});

// A declared block is the inverted case: it claims un-reachability, so it is
// attested by egress being *absent* under the profile while the baseline had it.
const blocked = (sandbox) =>
  attest({ ...INPUT, capabilitySet: load("capability-set-blocked"), sandbox });
const withoutEgress = (report) => ({
  ...report,
  findings: report.findings.filter((f) => f.findingType !== "external_host_connectivity"),
});

test("a declared network block the sandbox delivers is a match", () => {
  const r = blocked(withoutEgress(load("report-under-profile")));
  assert.equal(r.verdicts.find((v) => v.id === "network.block").class, "match");
  assert.ok(!r.gaps.some((g) => g.findingType === "external_host_connectivity"));
});

test("a declared network block with egress still observed is a gap", () => {
  const r = blocked(load("report-under-profile"));
  assert.equal(r.verdicts.find((v) => v.id === "network.block").class, "gap");
  // and every destination reached under it is undeclared, so it is a gap too
  assert.deepEqual(
    r.gaps.filter((g) => g.findingType === "external_host_connectivity").map((g) => g.host),
    ["api.openai.com", "api.github.com", "telemetry.example.net"],
  );
});

test("a declared network block is unprovable when the baseline had no egress either", () => {
  const r = attest({
    ...INPUT,
    capabilitySet: load("capability-set-blocked"),
    sandbox: withoutEgress(load("report-under-profile")),
    baseline: withoutEgress(load("report-baseline")),
  });
  assert.equal(r.verdicts.find((v) => v.id === "network.block").class, "unprovable");
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
