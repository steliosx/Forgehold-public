# Public source scope

This tree starts a new history for a source preview. Operational history, private inventories, historical review hashes, author/session records and run evidence are excluded. [Beta observations](BETA-OBSERVATIONS.md) gives a short summary of the private beta without those records. Generic project names, source fixtures, byte counts and digest bindings have been regenerated for this tree.

`fixtures/example-project/` is deliberately synthetic. Its files describe sample inputs, not a functional quality pipeline. The inventory hashes their exact bytes. Profiles remain disabled, with no runtime identities or authority. The model quality report is fabricated test data and must never be used as evidence of an actual run.

The 27-ID roster under `wrapper/scope/` describes a specific subset used by the supervisor's parser tests; it is not the count of the complete test suite. Existing schema labels are retained for compatibility with the source models.

Deployment references are renamed `.example`, not executable, and disabled before their operational content. [Packet from public](PACKET-FROM-PUBLIC.md) proposes how a lane packet could be rendered from this tree plus local deployment data. Their paths, identities, image pins and credential references are placeholders. Runtime version references are historical design examples, not recommendations to install those versions. A future deployment must independently select and review supported dependencies, configure every binding, and qualify the result on its intended host.

Local and hosted unit results qualify only the tested source. This release does not include live VM, isolation, cleanup, throughput or project-CI qualification evidence.
