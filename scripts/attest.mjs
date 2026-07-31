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
function covers(unit, path) {
  const g = trimSlash(unit.path);
  const p = trimSlash(path);
  return g === p || (unit.type !== "file" && p.startsWith(g === "/" ? "/" : `${g}/`));
}

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
        access,
        declaredPath: g.path,
        path: expandHome(g.path, home),
        type: g.type ?? "directory",
        findingType: FS_FINDING[access],
      });
    }
  }
  // ponytail: filesystem.deny declares *un*reachability, not a grant. A denied
  // path that turns up reachable already falls out as a gap, which is the
  // security-relevant verdict; give deny its own class only if that stops holding.

  const n = cs.network ?? {};
  if (n.mode) push("network.mode", { category: "network", reason: NOT_MAPPED });
  if (n.allow_domains?.length) push("network.allow_domains", { category: "network", reason: NOT_MAPPED });
  if (n.ports) push("network.ports", { category: "network", reason: NOT_MAPPED });
  if (n.endpoints?.length) push("network.endpoints", { category: "network", reason: NO_FINDING });

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
    if (observed(sandbox, u.findingType).some((p) => covers(u, p))) return { ...u, class: "match" };
    // Declared, not observed — an overclaim only if the baseline could reach it.
    // Nothing there to reach in the first place is unprovable, not a failure.
    if (observed(baseline, u.findingType).some((p) => covers(u, p))) return { ...u, class: "overclaim" };
    return { ...u, class: "unprovable" };
  });

  // Reachable with nothing declaring it: the security-relevant direction, kept in
  // its own list rather than pooled with the declared-side verdicts.
  const gaps = [];
  for (const findingType of Object.values(FS_FINDING)) {
    for (const path of observed(sandbox, findingType)) {
      if (!units.some((u) => u.findingType === findingType && covers(u, path))) {
        gaps.push({ class: "gap", findingType, path });
      }
    }
  }

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
