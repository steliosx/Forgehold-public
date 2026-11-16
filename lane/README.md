# Lane source reference

The Python helpers illustrate input validation, evidence custody, host inspection, queue admission and signed review handling. They are not a configured deployment. The allowlist is synthetic; reviewer keys are `UNCONFIGURED`; no runtime authority, watcher state, active packet manifest or credentials are included. Do not execute the command-line entrypoints against a real host without a separately configured and reviewed deployment.

Unit tests import only selected helpers and use temporary data. Deployment references are under `examples/deployment/`; the public CI does not use them. [docs/PACKET-FROM-PUBLIC.md](../docs/PACKET-FROM-PUBLIC.md) proposes how a lane packet could be built from this tree.
