// Profile attestation: diff a *declared* nono capability set against what the
// probe *observed*, and say how much of the declared surface was attestable at
// all. See CONTEXT.md ("Attestation" and the drift classes) and spec
// controlplaneio/sandbox-probe#4.
//
// Pure function over three documents — a resolved capability set, the report
// from a scan under that profile, and the same-host seeded unconfined baseline.
// No nono binary, no network, no side effects: everything stateful (profile
// fetch, Sigstore, pack install, the sandboxed run) is glue outside this file.
//
// The declared side is the *resolved* capability set (nono's capability
// manifest), never the authored profile: groups, aliases and bypasses are
// already expanded there, and re-implementing nono's resolver is not the job.

// The two filesystem axes this layer observes today.
const FS_FINDING = { read: "sensitive_readable_paths", write: "writeable_paths" };
// A readwrite grant is two declarations: both findings are needed to confirm it.
const ACCESS_UNITS = { read: ["read"], write: ["write"], readwrite: ["read", "write"] };

// Egress: `external_host_connectivity` alone, not folded with DNS. The probe only
// records connectivity for a host it *first resolved*, so the connectivity finding
// already means "resolved and connected"; `external_host_dns_resolution` carries
// resolved IPs, which cannot be matched back to a declared domain.
const EGRESS_FINDING = "external_host_connectivity";
// Ports: TCP only. nono's port declarations are TCP-only (no UDP field anywhere in
// its schema), so `udp_ports_open` has nothing on the declared side to diff against.
const PORT_FINDING = "tcp_ports_open";

// Findings nono has nothing to declare for by design — it mediates by policy and
// never swaps a namespace or a rootfs. Excluded from the diff entirely: these can
// never be gaps, however reachable they are.
export const UNDECLARABLE = [
  "mounted_volumes_detections",
  "hostname_detection",
  "user_context_detection",
];

const NO_FINDING = "no probe finding observes this category";
const NOT_MAPPED = "not yet mapped in this layer";

const trimSlash = (p) => p.replace(/\/+$/, "") || "/";
const expandHome = (p, home) => (home && p.startsWith("~") ? home + p.slice(1) : p);

// nono grants use `~` and may be recursive directories; the probe reports absolute
// expanded paths. Without the home expansion every `~` grant reads as a false
// overclaim, which is the one thing this whole design exists to avoid.
function coversPath(unit, path) {
  const g = trimSlash(unit.path);
  const p = trimSlash(path);
  return g === p || (unit.type !== "file" && p.startsWith(g === "/" ? "/" : `${g}/`));
}

// A leading dot is nono's suffix wildcard (`.githubusercontent.com` covers
// `raw.githubusercontent.com` and the bare apex); anything else is exact.
const coversDomain = (unit, host) =>
  unit.domain.startsWith(".")
    ? host === unit.domain.slice(1) || host.endsWith(unit.domain)
    : host === unit.domain;

// One matcher per declared-unit kind: does this observed value satisfy the unit.
const COVERS = {
  path: coversPath,
  domain: coversDomain,
  port: (unit, port) => unit.port === port,
  any: () => true,
};
const covers = (unit, value) => COVERS[unit.kind](unit, value);

const finding = (report, ft) => report?.findings?.find((f) => f.findingType === ft);
const observed = (report, ft) => {
  const v = finding(report, ft)?.value;
  return Array.isArray(v) ? v : [];
};

// One declared unit per thing the capability set claims. Units with a findingType
// are attestable; the rest carry the reason nothing here observes them and are
// reported as unattested rather than quietly dropped (silence must not read as a
// pass, and must never inflate coverage).
function declaredUnits(cs, home) {
  const units = [];
  const push = (id, u) => units.push({ id, ...u });

  for (const g of cs.filesystem?.grants ?? []) {
    for (const access of ACCESS_UNITS[g.access] ?? []) {
      push(`filesystem.${access}:${g.path}`, {
        category: "filesystem",
        kind: "path",
        access,
        declaredPath: g.path,
        path: expandHome(g.path, home),
        type: g.type ?? "directory",
        declares: FS_FINDING[access],
        findingType: FS_FINDING[access],
      });
    }
  }
  // ponytail: filesystem.deny declares *un*reachability, not a grant. A denied
  // path that turns up reachable already falls out as a gap, which is the
  // security-relevant verdict; give deny its own class only if that stops holding.

  const n = cs.network ?? {};
  // `mode: "blocked"` is nono's resolved form of `network.block` — an *inverted*
  // declaration: it claims un-reachability, so it is attested by egress being
  // absent under the profile while the baseline had it. Every other mode says how
  // egress is mediated, not whether any given destination is reachable; the
  // domains and ports below are the grants under it.
  if (n.mode === "blocked") {
    push("network.block", { category: "network", kind: "any", polarity: "absent", declares: EGRESS_FINDING, findingType: EGRESS_FINDING });
  } else if (n.mode) {
    push("network.mode", { category: "network", reason: NOT_MAPPED });
  }

  for (const d of n.allow_domains ?? []) {
    push(`network.allow_domains:${d}`, { category: "network", kind: "domain", domain: d, declares: EGRESS_FINDING, findingType: EGRESS_FINDING });
  }

  // An endpoint declares its host *and* a method/path rule on top. The host is a
  // declaration — egress to it is never a gap — but the probe only observes host
  // reachability, so the L7 half is unattested rather than quietly passed.
  for (const e of n.endpoints ?? []) {
    push(`network.endpoints:${e.host}`, {
      category: "network",
      kind: "domain",
      domain: e.host.replace(/:\d+$/, ""),
      declares: EGRESS_FINDING,
      reason: NO_FINDING,
    });
  }

  // `ports.localhost` (connect+bind) and `ports.listen` both resolve to ports the
  // child may hold open on localhost, which is exactly what the probe scans.
  for (const [where, ports] of Object.entries(n.ports ?? {})) {
    for (const port of Array.isArray(ports) ? ports : []) {
      push(`network.ports.${where}:${port}`, { category: "network", kind: "port", port, declares: PORT_FINDING, findingType: PORT_FINDING });
    }
  }

  for (const c of cs.credentials ?? []) {
    push(`credentials:${c.name}`, { category: "credentials", reason: NO_FINDING });
  }

  const p = cs.process ?? {};
  if (p.process_info_mode) push("process.process_info_mode", { category: "process", reason: NOT_MAPPED });
  if (p.signal_mode) push("process.signal_mode", { category: "process", reason: NO_FINDING });
  if (p.ipc_mode) push("process.ipc_mode", { category: "process", reason: NO_FINDING });
  if (p.allowed_commands?.length || p.blocked_commands?.length) {
    push("process.commands", { category: "process", reason: NO_FINDING });
  }

  for (const k of ["memory_bytes", "max_processes"]) {
    if (cs.resources?.[k] != null) push(`resources.${k}`, { category: "resources", reason: NO_FINDING });
  }

  return units;
}

/**
 * @param {object} input
 * @param {{id: string, version: string}} input.profile  declared profile identity
 * @param {object} input.capabilitySet  nono's resolved capability manifest
 * @param {object} input.sandbox  probe report from the run under the profile
 * @param {object} input.baseline  probe report from the seeded unconfined run
 * @param {string} [input.home]  home directory the reports were produced under
 */
export function attest({ profile, capabilitySet, sandbox, baseline, home }) {
  // A verdict that cannot be traced to an exact published claim is worthless.
  if (!profile?.id || !profile?.version) {
    throw new Error("attest: profile.id and profile.version are required — a verdict must name the claim it checked");
  }

  const units = declaredUnits(capabilitySet, home);

  const verdicts = units.map((u) => {
    if (!u.findingType) return { ...u, class: "unattested" };
    const underProfile = observed(sandbox, u.findingType).some((v) => covers(u, v));
    const inBaseline = observed(baseline, u.findingType).some((v) => covers(u, v));
    // An inverted declaration (a declared block) is delivered by *absence*: still
    // reachable means the sandbox is looser than its published claim, which is a
    // gap, the security-relevant direction.
    if (u.polarity === "absent") {
      if (underProfile) return { ...u, class: "gap" };
      return { ...u, class: inBaseline ? "match" : "unprovable" };
    }
    if (underProfile) return { ...u, class: "match" };
    // Declared, not observed — an overclaim only if the baseline could reach it.
    // Nothing there to reach in the first place is unprovable, not a failure.
    return { ...u, class: inBaseline ? "overclaim" : "unprovable" };
  });

  // Reachable with nothing declaring it: the security-relevant direction, kept in
  // its own list rather than pooled with the declared-side verdicts. An inverted
  // unit declares un-reachability, so it never suppresses a gap.
  const gaps = [];
  for (const findingType of [...Object.values(FS_FINDING), EGRESS_FINDING]) {
    for (const value of observed(sandbox, findingType)) {
      const declared = units.some(
        (u) => u.declares === findingType && u.polarity !== "absent" && covers(u, value),
      );
      if (declared) continue;
      gaps.push(
        findingType === EGRESS_FINDING
          ? { class: "gap", findingType, host: value }
          : { class: "gap", findingType, path: value },
      );
    }
  }
  // ponytail: no gap pass over open ports. A port the profile never declared is
  // one the child did not open either — the probe scans localhost, so it sees the
  // host's own listeners, not the sandbox's. Add one if that stops holding.

  const attested = units.filter((u) => u.findingType).length;
  return {
    profile: { id: profile.id, version: profile.version, manifestVersion: capabilitySet.version },
    verdicts,
    gaps,
    excluded: UNDECLARABLE.filter((ft) => finding(sandbox, ft) !== undefined),
    coverage: {
      declared: units.length,
      attested,
      unattested: units.length - attested,
      attestedFraction: units.length ? attested / units.length : 0,
    },
  };
}
