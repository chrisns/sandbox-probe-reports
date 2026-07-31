# sandbox-probe-reports

The **comparison and reporting harness** built on top of
[`sandbox-probe`](https://github.com/controlplaneio/sandbox-probe).

`sandbox-probe` is a single static Go binary you drop *inside* a sandbox to
report what it can see and reach. It is self-contained and useful on its own.
This repository is the other half: everything that turns many probe reports
into a comparison — the scan matrix, the seeder, the per-runtime launchers,
the agent stubs, the baseline-normalised methodology, and the reporting site.

> **Status: staging.** This repo currently lives under `chrisns` while the
> split settles; it is destined for `controlplaneio`. Only the dependency
> edge and its smoke job have landed so far — see [What lands here](#what-lands-here).

## Why this is a separate repo

Comparing sandboxes is a different piece of software with a much harder
problem — *what counts as a fair comparison?* — and it was generating churn
inside the probe's repo without touching the probe's own behaviour.
Splitting it means the probe stays stable and small, and the comparison
methodology can evolve (including being wrong and getting corrected) without
that ever destabilising the thing people depend on.

That "being wrong and getting corrected" is not hypothetical. The split was
triggered by discovering that the existing comparison rows for five sandbox
runtimes were not measuring what they claimed to — see
[Methodology](#methodology).

## Dependency on the probe

This repo carries its own `go.mod` requiring a pinned
`github.com/controlplaneio/sandbox-probe`, rather than checking the probe out
at a ref. Dependabot's `gomod` ecosystem tracks a `go.mod` requirement
automatically and resolves off git tags directly; a `ref:` pinned inside a
workflow is an opaque string nothing watches, and would rot silently.

The requirement is declared with Go's **`tool` directive**, not a bare
`require`:

```
tool github.com/controlplaneio/sandbox-probe
```

That matters. This repo imports no probe package — it *runs the binary*. A
bare `require` is therefore unused, and `go mod tidy` deletes it, taking the
Dependabot coverage with it and leaving no trace. The `tool` directive is the
mechanism the toolchain provides for exactly this case, and the smoke job
asserts the pin survives a tidy so it cannot rot back.

Build the pinned probe with:

```sh
go build -o bin/sandbox-probe github.com/controlplaneio/sandbox-probe
```

### The pin is currently a placeholder

It points at **`v1.1.0`**, which is not the version anyone wants:

- The probe's `v4.x` tags are **not resolvable as Go module versions**. The
  module path is `github.com/controlplaneio/sandbox-probe` with no `/v4`
  suffix, so the proxy rejects them (*"module path must match major
  version"*). `v1.1.0` is the newest tag that resolves at all.
- `v1.1.0` predates `list-targets`, so **the smoke job's seed step fails**
  against it. That is honest signal, not a bug in the job: the registry
  contract genuinely is not there yet.

Both clear when the probe's release pipeline is fixed
([controlplaneio/sandbox-probe#14](https://github.com/controlplaneio/sandbox-probe/issues/14))
and cuts a tag whose major version matches its module path. Then this is a
one-line bump — which Dependabot will raise on its own.

## The smoke job

`.github/workflows/smoke.yml` runs on **every push and pull request**,
including from forks. It needs no agent CLI, no API key, no model access and
no sandbox runtime — the opposite of the full matrix:

```
assert the probe pin survives `go mod tidy`
go build the probe            # version resolved from go.mod — the Dependabot pin
run the seeder against it     # reads list-targets across the repo boundary
run one direct baseline scan
assert the report parses and carries an expected finding type
```

One job, three failure modes it exists to catch:

- **The pin is dropped or broken** — tidy assertion, or the build step.
- **The binary is unusable** — a scan producing no parseable report fails
  here rather than in the next weekly matrix run.
- **The registry contract drifts** — the seeder reads `list-targets` from a
  now-external module. A schema change in the probe that the seeder cannot
  parse fails here. This is the drift the split makes possible and nothing
  else catches.

## What lands here

Per the repo-split decision (recorded in the wayfinder maps under `.scratch/`
in `sandbox-probe`):

- ✅ `go.mod` — the pinned probe dependency
- ✅ `scripts/seed-decoys.sh` — parent-side canary seeding
- ✅ `.github/workflows/smoke.yml` — the boundary smoke job
- ✅ `.github/workflows/scan-matrix.yaml` — the per-harness × OS scan matrix
- ✅ `.github/workflows/scan-gemini.yaml` — the standalone Gemini sandbox-image scan
- ✅ `scripts/run-probe-in-sandbox.sh` + the per-agent stub runners, the shared
  `stub-common.sh` plumbing, `mock-agent-api.mjs`, and the agent run scripts
- ✅ `tests/agent-driven/*.sh` — the baseline/sandbox pair scripts
- ✅ `reports/*.json`, `trajectories/*.json` — the stored fixtures
- ⏳ `site/` — the client-side reporting page, and the matrix's aggregate/publish job
- ⏳ `docs/reporting-site-plan.md` and the comparison-methodology ADRs

**Staying** in `sandbox-probe`: the Go binary (`cmd/`, `pkg/`, `main.go`), its
tests, and `list-targets` — the probe's own registry of what it checks, which
belongs next to the code it describes so the seeder cannot drift from it.
Also staying: `tests/fingerprint/*.sh` and the minimal `run-bwrap.sh` /
`run-docker.sh` / `run-podman.sh` launchers they invoke. Those assert that the
probe's own `sandbox_detection` identifies a runtime — a probe capability, not
a comparison. That is the line between `tests/fingerprint` and the
`tests/agent-driven` scripts that came here.

## Running the matrix

`scan-matrix.yaml` keeps its weekly cron, its `workflow_dispatch`, and its
`matrix/**` push trigger. Its `build` job compiles the probe **from the module
version pinned in `go.mod`** — `go build github.com/controlplaneio/sandbox-probe`
— once per platform, with darwin built on macOS and windows on Windows, and
shares the binaries to the scan jobs as artifacts. Nothing but that binary
comes from outside this repository: every script, stub and config the scan rows
invoke resolves under `scripts/` here.

**History does not migrate.** Files arrive as a fresh commit; the decision
record lives in the ADRs and wayfinder maps rather than in `git log`.

## No current data here yet

This repository publishes no comparison results at the moment. The dormant
`controlplaneio/sandbox-probe-reports` still carries a single `gemini/` sample
directory from March 2026 — **that is a stale sample, not current data**, and
it is removed as part of the migration. Nothing under this repo is a
published result until the scan matrix lands and the data branch starts
publishing.

## Methodology

Two ideas do the load-bearing work.

**Baseline normalisation.** A finding's *absence* only means "the sandbox
blocked it" if the capability was achievable on that host at all. Everything
is read against an unconfined same-OS baseline run: leaked (baseline could,
this harness still can), blocked (baseline could, this harness cannot), n/a
(baseline could not either — nothing was proven).

**Canary nesting.** Canaries are seeded in the *parent* host, and the sandbox
is launched as a genuine child of that seeded parent. The question is whether
a process inside the sandbox can reach out to something outside it. Canaries
are never planted *inside* the sandbox: that would test whether the sandbox's
own environment happens to contain artefacts, which is not the threat model —
a real attacker in a real sandbox is trying to reach *out*.

This is also why the five rootfs-swapping runtimes (docker, podman, bwrap,
nspawn, gvisor, driven directly with no agent) were **retired from the
comparison** rather than fixed. Each was launched as a fresh, disconnected
environment that had never been nested in the seeded parent, so "the sandbox
blocked it" was indistinguishable from "there was never a route there to
begin with". Any sharing flags the harness adds to reconnect them are the
harness's own choice, not a vendor's — so the result would measure our
configuration rather than the sandbox's. Comparisons are only kept where
*someone else* made the configuration decision: an agent vendor shipping its
own sandbox, or a declared, versioned policy profile.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) — the same licence as `sandbox-probe`.
