# Architecture and evidence boundaries

The intended flow is: reviewed source and job inputs → admission checks → one bounded execution → sealed evidence → independent review. Queue helpers retain holds when state is uncertain; data validation and a receipt do not grant execution authority.

The B1 model validates canonical JSON, exact hashes, disabled profiles and independently supplied registry bindings. Its live submission paths refuse. The linking layer checks local observations without promoting them to remote authenticity.

The supervisor has injectable I/O and process seams. Unit tests use fakes for execution and clocks, plus temporary files for filesystem checks. They cover framing, partial output, failure provenance, deadline checks and evidence receipt behavior. Real descendants, VM lifetime, engine cancellation and hard whole-attempt completion require separate runtime tests.

The lane reference includes allowlist validation, input custody, queue state transitions, process classification and signed-review checks. Its identity pins are unconfigured and its allowlist is synthetic. The CI suite does not start the queue, watcher, engine or service units.

Forgehold's intended Preloop integration is distinct from enrolling a GitHub Actions self-hosted runner. This repository supplies neither runner enrollment nor a working installation wizard.
