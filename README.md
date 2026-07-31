# sandbox-probe-reports

The **comparison and reporting harness** built on top of
[`sandbox-probe`](https://github.com/controlplaneio/sandbox-probe).

> **Status: staging.** This repo currently lives under `chrisns` while the
> split settles; it is destined for `controlplaneio`. Nothing here is
> migrated yet — see [What lands here](#what-lands-here).

## Why this is a separate repo

`sandbox-probe` is a single static Go binary you drop *inside* a sandbox to
report what it can see and reach. That is self-contained and useful on its
own: run it, read the output.

Everything about **comparing** sandboxes is a different piece of software
with a much harder problem — *what counts as a fair comparison?* — and it
was generating churn inside the probe's repo without touching the probe's
own behaviour. Splitting it means the probe stays stable and small, and the
comparison methodology can evolve (including being wrong and getting
corrected) without that ever destabilising the thing people depend on.

That "being wrong and getting corrected" is not hypothetical. The split was
triggered by discovering that the existing comparison rows for five
sandbox runtimes were not measuring what they claimed to — see
[Methodology](#methodology).

## What lands here

Per the repo-split decision (recorded in the wayfinder maps under
`.scratch/` in `sandbox-probe`):

- `.github/workflows/scan-matrix.yaml` — the per-harness × OS scan matrix
- `scripts/seed-decoys.sh` — parent-side canary seeding
- `scripts/run-probe-in-sandbox.sh` + the per-agent stub runners
- `tests/*.sh` — the baseline/sandbox pair scripts
- `site/` — the client-side reporting page
- `docs/reporting-site-plan.md` and the comparison-methodology ADRs

**Staying** in `sandbox-probe`: the Go binary (`cmd/`, `pkg/`, `main.go`),
its tests, and `list-targets` — the probe's own registry of what it checks,
which belongs next to the code it describes so the seeder can't drift from
it.

**History does not migrate.** Files arrive as a fresh commit; the decision
record lives in the ADRs and wayfinder maps rather than in `git log`.

## Dependency on the probe

This repo will carry its own `go.mod` requiring a pinned
`github.com/controlplaneio/sandbox-probe` version, rather than checking the
probe out at a ref. That is deliberate: Dependabot's `gomod` ecosystem
tracks a `go.mod` requirement automatically, whereas a `ref:` pinned inside
a workflow is an opaque string nothing watches, and would rot silently.

## Methodology

Two ideas do the load-bearing work.

**Baseline normalisation.** A finding's *absence* only means "the sandbox
blocked it" if the capability was achievable on that host at all.
Everything is read against an unconfined same-OS baseline run: leaked
(baseline could, this harness still can), blocked (baseline could, this
harness cannot), n/a (baseline could not either — nothing was proven).

**Canary nesting.** Canaries are seeded in the *parent* host, and the
sandbox is launched as a genuine child of that seeded parent. The question
is whether a process inside the sandbox can reach out to something outside
it. Canaries are never planted *inside* the sandbox: that would test
whether the sandbox's own environment happens to contain artefacts, which
is not the threat model — a real attacker in a real sandbox is trying to
reach *out*.

This is also why the five rootfs-swapping runtimes (docker, podman, bwrap,
nspawn, gvisor, driven directly with no agent) were **retired from the
comparison** rather than fixed. Each was launched as a fresh, disconnected
environment that had never been nested in the seeded parent, so "the
sandbox blocked it" was indistinguishable from "there was never a route
there to begin with". Any sharing flags the harness adds to reconnect them
are the harness's own choice, not a vendor's — so the result would measure
our configuration rather than the sandbox's. Comparisons are only kept
where *someone else* made the configuration decision: an agent vendor
shipping its own sandbox, or a declared, versioned policy profile.

## License

See `LICENSE` once migrated (`sandbox-probe` is Apache-2.0).
