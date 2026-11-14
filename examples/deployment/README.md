# Inactive deployment references

These files illustrate the relationship between a wrapper, supervisor, engine gate, queue and user service units. They are not a complete or installable package. All `.sh.example` files immediately refuse execution with exit 64. Unit examples have a deliberately unmet condition. None is used by hosted CI.

Paths under `/srv/forgehold/`, the `example-owner` account, unconfigured identities, zero App ID and synthetic digests are placeholders. No credentials are included. Do not enable a timer, copy these units into a service manager, remove their guards, or interpret them as an operational grant. Construct and review a separate deployment with current dependencies and an explicit authorization model first.
