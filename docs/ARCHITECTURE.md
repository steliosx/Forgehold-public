# Architecture and evidence boundaries

The intended flow is: reviewed source and job inputs → admission checks → one bounded execution → sealed evidence → independent review. Queue helpers retain holds when state is uncertain; data validation and a receipt do not grant execution authority.

The B1 model validates canonical JSON, exact hashes, disabled profiles and independently supplied registry bindings. Its live submission paths refuse. The linking layer checks local observations without promoting them to remote authenticity.

The supervisor has injectable I/O and process seams. Unit tests use fakes for execution and clocks, plus temporary files for filesystem checks. They cover framing, partial output, failure provenance, deadline checks and evidence receipt behavior. Real descendants, VM lifetime, engine cancellation and hard whole-attempt completion require separate runtime tests.

The lane reference includes allowlist validation, input custody, queue state transitions, process classification and signed-review checks. Its identity pins are unconfigured and its allowlist is synthetic. The CI suite does not start the queue, watcher, engine or service units.

Forgehold's intended Preloop integration is distinct from enrolling a GitHub Actions self-hosted runner. This repository supplies neither runner enrollment nor a working installation wizard.

## One attempt, step by step

The deployment references in `examples/deployment/` show how the private beta lane ran one attempt. They are inactive placeholders; the order below is what they encode.

1. **Admission, before any effect.** The wrapper checks the packet's own file hashes, the request, that no queue STOP or SUSPENDED marker exists, and that the host is ready: every thermal zone below 85 °C for three consecutive one-second readings, and at least 4.5 GiB of available memory. It then opens per-attempt custody (an evidence folder and a hold record).
2. **Engine start and readiness.** The supervisor starts the Preloop engine unit and waits until its runner pool reports the expected labels. Recovered work left in the engine stops the attempt.
3. **Pre-dispatch checks.** No VM of the lane's own may be running, the runner image hash must match its pin, and the host checks are repeated.
4. **One dispatch.** The supervisor sends a single `workflow_dispatch` request and never retries it. A check run must appear within 60 seconds and a runner must register within 300 seconds. A run is adopted only if its own record shows the expected repository, workflow and commit, and it was absent before the dispatch.
5. **One VM.** The engine creates one SmolVM guest through a gate that allows a single create per attempt, with fixed CPU, memory and storage settings and the strict egress floor.
6. **Completion and clean-up.** After the check completes, or the episode budget runs out, clean-up cancels only the verified run, stops the units and records named witnesses (own VM and engine processes). Clean-up has its own time ceiling.
7. **Result and seal.** The wrapper writes a result record and seals the evidence folder with a manifest. A run counts as a success only if every attribution check passes; anything not fully proven is not a PASS.

The standing queue adds its own gates in front of each attempt: one attempt at a time, a 60-second launch announcement, project holds re-checked just before launch, every thermal zone below 75 °C, and at least 5 GiB of available memory.

### Shared host

The lane shares its host with other projects' VMs. `lane/fh_hostscan.py` sorts processes into the lane's own (an executable under the lane's home, or a process inside the lane engine's service cgroup) and foreign (anything else). Foreign VMs are tolerated and recorded; the lane never stops or deletes them. A process of the lane's user whose executable and cgroup are both unreadable counts as unknown, and the check fails closed.
