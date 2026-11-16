#!/usr/bin/python3 -I

# run the lane alongside them). Counts processes by exact comm and splits them into OURS (the executable resolves
# under the lane's pilot home, e.g. @@FH_PILOT_DIR@@/.smolvm/smolvm-bin) and FOREIGN (anything else, e.g.
# the lab SmolVM @@FH_OPERATOR_HOME@@/.smolvm/smolvm-bin used by other projects). Observation only; it never signals anything.
#   fh_hostscan.py procs <comm>   -> prints "<own> <foreign>"; exit 0, or exit 2 if a matching process of our uid
#                                    has neither a readable executable nor a readable cgroup (fail closed). OURS also
#                                    covers any process in the forgehold-lane-b3.service cgroup (a non-dumpable VM
#                                    hides its executable). Other users' processes are foreign (lane runs as uid 1000).
#   fh_hostscan.py detail <comm>  -> one JSON line per matching process {pid, uid, own, exe, cgroup} (evidence only).
#   fh_hostscan.py lab <name>     -> reads a `smolvm machine ls --json` list on stdin; prints "<count> <names>";
#                                    exit 1 if an entry is named <name> (our machine must never be in the lab
#                                    registry), exit 2 if the input is not a JSON list of objects.
import json
import os
import sys

OWN_PREFIX = "@@FH_PILOT_DIR@@/"
OWN_CGROUP = "/forgehold-lane-b3.service"


def proc_uid(pid):
    # /proc/<pid>/status stays readable for non-dumpable processes (stat of /proc/<pid> then reports root).
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("Uid:"):
                return int(line.split()[1])
    return None


def scan(comm):
    out, unreadable = [], False
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as f:
                if f.read().rstrip("\n") != comm:
                    continue
        except OSError:
            continue  # exited between listdir and open, or not ours to read
        uid = exe = cg = None
        try:
            uid = proc_uid(pid)
        except FileNotFoundError:
            continue  # exited
        except (OSError, ValueError):
            pass
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except FileNotFoundError:
            continue  # exited
        except OSError:
            pass  # EACCES for other users' or non-dumpable processes
        try:
            with open(f"/proc/{pid}/cgroup") as f:
                cg = f.read().strip()
        except FileNotFoundError:
            continue  # exited
        except OSError:
            pass
        # OURS: executable under the pilot home, or inside the lane unit's cgroup (the engine's children stay there).
        own = bool(exe and exe.startswith(OWN_PREFIX)) or bool(cg and OWN_CGROUP in cg)
        # Unknown, fail closed: a process of our uid (or unknown uid) whose executable AND cgroup are both unreadable.
        # Another user's process is never ours (the lane runs as uid 1000).
        if not own and exe is None and cg is None and (uid is None or uid == os.getuid()):
            unreadable = True
        out.append({"pid": int(pid), "uid": uid, "own": own, "exe": exe, "cgroup": cg})
    return out, unreadable


def main(argv):
    if len(argv) != 3:
        return 64
    mode, arg = argv[1], argv[2]
    if mode == "procs":
        procs, unreadable = scan(arg)
        own = sum(1 for p in procs if p["own"])
        print(own, len(procs) - own)
        return 2 if unreadable else 0
    if mode == "detail":
        procs, unreadable = scan(arg)
        for p in procs:
            print(json.dumps(p, sort_keys=True))
        return 2 if unreadable else 0
    if mode == "lab":
        try:
            d = json.loads(sys.stdin.read())
            assert isinstance(d, list) and all(isinstance(m, dict) for m in d)
        except Exception:
            return 2
        names = [str(m.get("name")) for m in d]
        # Printed names are restricted to [A-Za-z0-9._-] so the line can be embedded in a JSON string.
        safe = ["".join(c if c.isascii() and (c.isalnum() or c in "._-") else "?" for c in n) for n in names]
        print(len(d), ",".join(safe) or "-")
        return 1 if arg in names else 0
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
