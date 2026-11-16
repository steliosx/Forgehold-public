# Inactive deployment references

These files illustrate the relationship between a wrapper, supervisor, engine gate, queue and user service units. They are not a complete or installable package. All `.sh.example` files immediately refuse execution with exit 64. Unit examples have a deliberately unmet condition. None is used by hosted CI.

Deployment values (paths, accounts, identities, the App ID, pins and digests) are named tokens such as `@@FH_QUEUE_DIR@@`; `lane/render_packet.py` lists every token and its type. The guards stay in these files: only the render tool removes them, in a rendered packet outside any clone, from local deployment data that is never part of this repository. No credentials are included. Do not enable a timer, copy these units into a service manager, remove their guards, or interpret them as an operational grant. Construct and review a separate deployment with current dependencies and an explicit authorization model first.
