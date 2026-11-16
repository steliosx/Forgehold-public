# Forgehold

Forgehold explores a controlled CI execution lane built around Preloop and SmolVM: explicit job inputs, source bindings, bounded execution, and retained evidence for independent review.

Two design rules apply throughout. Use Preloop and SmolVM wherever they already provide a function, and add Forgehold code only for what they lack (job profiles and validation, pinned evidence, fail-closed result checking). And turn every result into a strict PASS, REFUSED or UNKNOWN record: anything that is not fully proven is not a PASS.

**This is a source preview with synthetic examples, not an installable runner or a qualified production deployment.** Its immediately usable CI is the Python unit suite on standard GitHub-hosted runners. Those tests do not boot a VM, exercise a real engine, or prove isolation or cleanup on a live host.

**Status (15 November 2026):** the private beta lane is active again. This repository stays a source subset of it: it does not carry the active lane's packet, allowlist, run records or deployment state.

## Run the unit tests

Use Python 3.14 on Linux. The suites use the standard library and require no dependency installation:

```sh
python3 -I -B -m unittest discover -s tests -t . -v
python3 -I -B -m unittest discover -s wrapper/tests -t . -v
```

The suites contain 102 adapter/link/queue/render tests and 80 supervisor tests. One filesystem-permission test is skipped if run as root; use an ordinary user for the complete check. Hosted CI runs on push to `main` or `release-preview/**`, pull requests, and manual dispatch. A ruleset protects the default branch: every change needs a pull request, and the `unit` check must pass. A second workflow audits the workflow files with zizmor; it is informational, not a required check.

## Source map

- `forgehold_b1/`: strict data validation and a model adapter. A valid model result cannot submit a live job or publish a check.
- `wrapper/`: a bounded test supervisor and mock-based tests for framing, custody, errors and deadlines. Its receipt alone cannot prove a successful outer execution.
- `lane/`: reference helpers for admission, queue handling, workflow validation, host inspection and signed review evidence. These are unconfigured operational source, not a deployment package. `lane/render_packet.py` renders a packet from this tree plus local deployment data ([proposal](docs/PACKET-FROM-PUBLIC.md)).
- `profiles/` and `fixtures/`: disabled profiles and synthetic project data. The reported tool versions and PASS records are model inputs, not results from executing those tools.
- `examples/deployment/`: inactive shell and service references with `@@FH_*@@` tokens. Shell examples exit before performing any operation; service examples have a deliberately unmet activation condition. Only the render tool removes these guards.

## Private beta record

From 2026-10-16 to 2026-11-06 Forgehold ran as a private beta lane on one laptop: 36 queued runs across four repositories, including five runtime probes. Runtime was never qualified. [Beta observations](docs/BETA-OBSERVATIONS.md) summarizes what the lane observed and what it does not show, and [the workflow subset](docs/WORKFLOW-SUBSET.md) lists the workflow and request rules a job had to meet.

## Scope and limitations

The adapter intentionally binds one synthetic project rather than offering a general enrollment API. No private project inventory, operational run record, mailbox key, credential, active authority record or runtime image is distributed. No runtime dependencies are installed by CI.

Source review, unit-test results, runtime qualification, and permission to operate a deployment are separate. A deployment needs its own reviewed configuration, current dependency/security assessment, explicit authority, signed identity setup, resource policy and end-to-end evidence. Nothing in this preview authorizes activation or claims that arbitrary GitHub Actions workflows are supported.

See [the architecture](docs/ARCHITECTURE.md), [the workflow subset](docs/WORKFLOW-SUBSET.md), [beta observations](docs/BETA-OBSERVATIONS.md), [release scope](docs/RELEASE-SCOPE.md), and [security reporting](SECURITY.md).

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Preloop and SmolVM are separately distributed upstream projects with their own licenses. They are not vendored here.
