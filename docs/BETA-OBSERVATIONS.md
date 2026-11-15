# Private beta observations (2026-10-16 to 2026-11-06)

Before this source preview, Forgehold ran as a private beta lane on one Linux laptop. This page summarizes what that lane observed. It is a summary of operator reports, not evidence: run records, logs, inventories, identities and check links stay private. Explanations of causes are marked "operator reading"; they were not independently established.

Runtime was **not qualified** at any point. None of the results below proves enforced isolation, egress control, secret absence or clean-up.

## How the lane ran

- The first lane run was on 2026-10-16. From 2026-10-30 the lane ran as a standing queue: one request at a time, each in a new single-use SmolVM micro-VM driven by a local Preloop engine, with the result published as a GitHub App check run on the dispatched commit.
- These were local Preloop executions of GitHub-sourced workflows. They were not GitHub Actions self-hosted runner jobs, and a push did not start them. Each run was requested when the projects involved agreed on a time.
- The guest was configured with 1 vCPU, 3 GiB of memory and a strict egress floor. That is configuration, not proven enforcement.
- Before each launch the lane required a cool host and enough free memory, announced the request 60 seconds ahead, and re-checked project holds just before launch. The dispatch was a single attempt and was never retried.

## Results

From 2026-10-30 to 2026-11-03 the queue completed 36 runs across four repositories of the same owner, Forgehold among them:

| Outcome | Runs |
|---|---|
| Reported PASS | 27 |
| Failed by design (deliberate fault or time-limit probes) | 3 |
| Failed (see below) | 6 |

Every repository had a passing `smoke` job: the dispatched commit was checked out and two markers were printed. A smoke pass is not by itself evidence of App provenance, isolation or clean-up.

What the six real failures taught:

- A workflow pinned a Node.js 20 action after GitHub had removed Node.js 20 support for actions (2026-09-23). Pinning a current action release fixed it.
- A large test suite (3310 tests in one job) hit its own 240-second bound at about 29%. Operator reading: the 1-vCPU guest is much slower than the host. Splitting the suite into shards did not by itself fix this: one shard also hit the bound.
- Moving pytest's temporary files to tmpfs filled the guest's 64 MiB `/dev/shm` ("No space left on device"; operator reading).
- A job that required a writable, executable tmpfs refused to start because the guest had none.
- One shard of a six-shard set had 1 failure in 60 tests. Operator reading: an environment difference in the guest.

The conformance coverage of that large suite stayed incomplete.

## Guest inventory (probe, 2026-10-31)

Observation only:

- The guest reached every public host tested (GitHub, PyPI, crates.io, rust-lang, Ubuntu apt, Docker Hub, ghcr, npm). The strict egress floor is aimed at private address ranges.
- Tools: Python 3.12, gcc 13, Node 22, git and the Docker CLI.
- rustup is present, but rustc and cargo need a writable `RUSTUP_HOME`.
- `sudo` is unusable, so jobs cannot install packages with apt.
- The tool cache is empty.

A Docker probe on 2026-11-02 found the Docker CLI and daemon reachable and Docker Compose present; `docker run --rm hello-world` succeeded with an unpinned image. That is a capability survey, not proof of a usable Docker CI job, and container clean-up was not proven.

## Runtime observations (RQ-01, 2026-11-02 and 2026-11-03)

Five probe workflows ran once each (these five are among the 36 runs above):

- **secrets**, **egress**, **isolation**: lane PASS. In egress, the fixed private targets were refused and the public probes connected. The egress summary is NOT_QUALIFIABLE by design: a probe cannot prove that no other route exists.
- **crash** (deliberate fault): expected NOT_PASS.
- **hang** (deliberate fault with a 2-minute job limit): cancelled at the limit, expected NOT_PASS.

In the two recorded time-limit attempts (a 1-minute probe and the 2-minute hang probe), the job was cancelled at its `timeout-minutes` limit. That is evidence for those attempts only, not general timeout enforcement. A separate probe recorded that `pidfd_open` on the job's own process works in the guest.

On 2026-11-06 the retained records of all five probes were re-read offline with a pinned verifier and workflow-bound expectations. No probe was rerun.

- The crash and hang records satisfied nine retained clean-up text checks. Their trigger causes remain UNKNOWN.
- A fixed-pattern credential scan of the retained files found no hits. A few files were excluded from that scan and covered only by manifest integrity checks. Pattern scanning does not establish that no credentials were present.
- A verifier exit 0 means the retained records met that verifier's contract. It does not turn an intended failure into a success or explain why a fault occurred.

## What this does not show

- Runtime qualification, enforced isolation, egress enforcement or secret absence.
- General clean-up: the clean-up results concern recorded text witnesses, not an independent inspection of live processes.
- That arbitrary GitHub Actions workflows are supported. The lane accepted only a constrained workflow subset; see [the workflow subset](WORKFLOW-SUBSET.md).
- Anything about future behaviour, other hosts or other configurations.
