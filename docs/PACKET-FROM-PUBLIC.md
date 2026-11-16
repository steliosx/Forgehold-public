# Proposal: build the lane packet from this repository

Status: proposal (2026-11-15). Steps 1 to 3 are implemented (2026-11-16): the tokens, `lane/render_packet.py` and its tests. No rendered packet is active yet.

## Why

The private beta lane runs a frozen packet that was built from a private copy of this code. Development now continues only in this repository. The next packet must therefore come from this repository plus local deployment data, with no private source tree.

## What differs today

The lane files here are the running lane's files with three kinds of change: header comments are removed; a closed set of deployment values is replaced by placeholders (`/srv/forgehold/...`, `example-owner`, `UNCONFIGURED`, App ID `0`, synthetic digests); and each deployment script starts with a refusal (`exit 64`) and each unit with a condition that is never met. With comments and blank lines removed, the placeholder values, the guards and a few renamed names and reworded messages are the only remaining differences from the running packet:

| Lane file | Public counterpart | Differing code lines |
|---|---|---|
| `fh_custody.py`, `fh_input.py`, `fh_workflow.py` | `lane/` | 0 |
| `fh_hostscan.py`, `fh_queue.py`, `fh_watch.py` | `lane/` | 2, 4, 16 |
| `queue_run.sh`, `run_fh_b3.sh`, `supervise_fh_b3.sh`, `smolvm-gate-fh-b3.sh` | `examples/deployment/*.example` | 10, 42, 38, 24 (including the 2-line guard) |
| engine, queue and watch units, socket, timer | `examples/deployment/*.example` | 37, 9, 3, 1, 1 (including the never-met condition) |

Three packet files have no public counterpart: the allowlist and the watch list (both deployment data, copied from the local config directory) and the checksum list (generated). A historical run-scope note is dropped.

## Proposal

1. **Named placeholders.** Replace each placeholder with a named token from one closed list, for example `@@FH_QUEUE_DIR@@`, `@@FH_EVIDENCE_ROOT@@`, `@@FH_OWNER@@`, `@@FH_REVIEWER_ID@@`, `@@FH_REVIEWER_PUBKEY@@`, `@@FH_APP_ID@@`, `@@FH_APP_KEY_FILE@@`: 30 in all. The packet directory itself supplies two of them (`@@FH_PACKET_DIR@@`, `@@FH_PACKET_NAME@@`); the local config supplies the other 28, each with a type (path, digest, key, identifier).
2. **One render tool**, `lane/render_packet.py <repository tree> <config.json> <output directory>`, standard library only. It refuses an unknown token, a missing value, or a token left in any output; checks each value's type (absolute path, hex digest, identifier; no newline or quote); refuses an output directory inside a git work tree; creates the packet directory itself and never replaces one; writes every file read-only with a checked write loop, then the checksum list and a `RENDER.json` that names the repository commit, the config's SHA-256 and the tool version; reads every file back against the manifest before it sets the directory read-only; and on failure removes only what it made, or reports that the output was retained. The same inputs give the same bytes. Public CI renders a synthetic config and checks the result.
3. **The guard stays.** Each script and unit keeps its refusal until it is rendered: an unrendered file still exits 64 or never starts. Only the render tool removes the guard, and it refuses a file whose guard is missing. Nothing in this repository runs as it is, and the repository stays a source preview, not an installable runner.
4. **Local only, never in this repository:** the config file (read-only, outside any clone), the allowlist, the App key (referenced by path only), evidence, queue state and mailbox roots.
5. **Review and activation.** The reviewer gets the repository commit, the render report (every substitution) and the config and packet hashes. For the first rendered packet, the activation request also shows that each rendered file differs from the running packet only by the removed comments and the packet name. Activation keeps the existing procedure: stop the idle queue, retain the old record, install, relink one unit, start once, verify.

**Check against the running packet (2026-11-16).** Rendered with the running packet's values, 14 of the 17 rendered files have the same code lines as the running packet. The other three differ only in names and text: `fh_watch.py` names its key constants `REVIEWER_*` instead of after the reviewer and words one error message differently; `run_fh_b3.sh` and `supervise_fh_b3.sh` word two hold messages and one record string differently and drop one inline comment. The packet adds `RENDER.json` and drops the run-scope note.

Preloop and SmolVM have no function for packaging a reviewed deployment, so the render tool is new code for a gap (the first design rule in the README).

## Open questions

- **Allowlist:** local deployment data (proposed for now, because its entries name other projects' repositories and workflow hashes) or a public file.
- **Self-test:** a small lane workflow in this repository, so that the lane can test Forgehold itself again. The old Forgehold entries point to the archived private repository.

## Out of scope

Runtime qualification, a new execution model, and any change to the lane's gates (temperature, memory, one attempt, holds). Those change only through a reviewed packet.
