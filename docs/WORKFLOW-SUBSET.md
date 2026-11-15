# Accepted workflow subset and job requests

Forgehold does not run arbitrary GitHub Actions workflows. A job is eligible only if its workflow passes `lane/fh_workflow.py` and its request passes `lane/fh_input.py`. This page restates those rules; the source files are authoritative.

## Workflow rules (`lane/fh_workflow.py`)

- At most 65,536 bytes of UTF-8, exactly one YAML document, and a SHA-256 equal to the agreed `workflow_sha256`.
- Parsed with PyYAML 6.0.3 using `BaseLoader`, so every scalar stays a string. Any other PyYAML version refuses.
- No anchors, aliases, explicit tags or merge keys anywhere. No duplicate mapping keys at any level.
- Top-level keys only: `name`, `run-name`, `on`, `permissions`, `concurrency`, `env`, `defaults`, `jobs`.
- `on` is exactly `workflow_dispatch`: a scalar, a one-item list, or a mapping whose only key is `workflow_dispatch` with an empty value or a mapping without `inputs`.
- `jobs` holds exactly one job, whose ID is the agreed job.
- That job may use only `name`, `runs-on`, `timeout-minutes`, `steps`, `permissions`, `env`, `defaults`, `concurrency`. So reusable workflows (`uses`), matrices (`strategy`), `needs`, `if`, `services` and `container` are outside the subset.
- `runs-on` is exactly the labels `self-hosted`, `Linux`, `X64`, `forgehold`, each once, as a list.
- `timeout-minutes` is a literal integer from 1 to 6. `steps` is a non-empty list of mappings.

The `runs-on` labels describe the accepted subset. They do not mean that a GitHub Actions self-hosted runner is registered.

This is structural validation only. It does not inspect what each step, action or called script does. A workflow hash pins the workflow file, not the scripts it runs: those can change with new commits on the allowed branch.

## Request rules (`lane/fh_input.py`)

A request (`FH_LANE_INPUT_1`) is a JSON object of at most 16,384 bytes, with no duplicate or unknown keys:

- `repository`: the repository name (letters, digits, `_`, `.`, `-`; up to 100 characters).
- `workflow`: the workflow file name, ending in `.yml` or `.yaml`; `workflow_sha256`: 64 lowercase hex characters.
- `job`: the job ID (letters, digits, `_`, `-`; up to 64 characters).
- `ref`: an unqualified branch name (not `refs/...`). Up to 100 characters; no `..`, no part starting with `.` or `-`, no part ending in `.lock`, and the whole name does not end in `.`.
- `commit`: the full 40-character commit.
- `log_required` and `log_forbidden`: up to 16 fixed strings each, 1 to 200 printable ASCII characters.
- `ok_lines`: the exact expected number of `OK` lines, 0 to 64.
- `expiry_epoch`: an integer Unix time. The parser checks its range, not that it is still in the future.
- `note`: optional, up to 500 characters.

The allowlist binds the repository, workflow hash, job and exact ref (or a permitted ref prefix), together with the log expectations. Staging uses the live head of the ref, so record the exact commit you intend in the request: a branch name alone does not identify one attempt. A check made before dispatch does not atomically pin the commit the engine later fetches.

Log markers are fixed-string checks. Matching them and counting `OK` lines does not prove test coverage, trustworthy execution, isolation or clean-up.

## Request outline

This outline is for human review. It is not valid machine input and not a queue submission.

- Project contact and the check you want: …
- Repository owner and name: …
- Workflow file name, SHA-256 of its exact bytes, and the single job ID: …
- Unqualified branch name and the exact 40-character commit: …
- Required markers, forbidden markers, and the exact expected `OK`-line count: …
- Expiry in local time with its UTC offset, and the same moment as an integer epoch: …
- What the job does, which scripts and actions it uses, the expected outcome and any environment needs: …

## Reading a result

Keep four things separate: acceptance of exact source bytes; the tests that actually ran and their outcomes; runtime qualification; and usable CI for one project and job. A pass in one does not imply the others.
