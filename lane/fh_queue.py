#!/usr/bin/python3 -I


#   fh_queue.py authority <ACTIVE.json> <packet_dir>     -> exact packet path + SHA256SUMS hash + ALLOWLIST hash bound
#   fh_queue.py select <queue_dir> <packet_dir>          -> prints the oldest valid request path, or exits 3 (none)
#   fh_queue.py stage <request> <input_dir> <packet_dir> -> resolves the live ref head, writes INPUT.json/INPUT.sha256
#                                                          (0400) and moves the request to claimed/ (intent record)
#   fh_queue.py record <queue_dir> <id> <rc> <stdout>    -> writes done/<id>.json; exit 0 = clean terminal, 1 = suspend
#   fh_queue.py notrun <queue_dir> <id> <reason>          -> claimed request not launched (stop, thermal, lock taken,
#                                                          setup failed): done/<id>.json
# Q09-2: the enqueue time is the UTC stamp in the request file name (<YYYYmmddTHHMMSSZ>-<label>.json). A name more than
# 60 s in the future is invalid; a request whose enqueue time is 24 h old or older is NOT_RUN (retained in rejected/,
# never staged). The check runs at selection and again at staging (after every wait). expiry_epoch = enqueue + 24 h,
# never refreshed, so run_fh_b3.sh's own now < expiry - 600 refusal also bounds a request's life.
# Requests (FH_QUEUE_REQUEST_1, one JSON file each in <queue_dir>/requests/) name an allowlisted repository + ref +
# workflow + job; the commit is the live ref head at staging (optional "commit" must equal it, else rejected as stale).
# Each request id runs at most once (claimed/ before launch, never requeued). A workflow pin is NOT complete job-code
# review: scripts the workflow calls may change on any commit of the allowlisted ref (deliberate owner policy, 57).

# branch prefix ending in "/") instead of "ref". It admits a request whose concrete ref is <prefix><tail> for the same
# repository/workflow/job; the INPUT and everything downstream carry only that concrete ref, never the prefix. An exact
# ref under a prefix of the same (repository, workflow, job), or nested prefixes, refuse the whole allowlist at load.
# Prefix keys hold a tuple in the ref slot: a lookup by a 4-string key (fh_watch WATCH.json) finds exact entries only.
import calendar
import hashlib
import json
import os
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True  # the packet dir is frozen; never write __pycache__ into it
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fh_input  # noqa: E402  (same packet; FH_LANE_INPUT_1 validator)

ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-z0-9-]{1,40}")
WHO = re.compile(r"[a-z0-9-]{1,40}")
REQ_KEYS = {"schema", "repository", "ref", "workflow", "job", "requested_by", "commit", "note"}
ENTRY_KEYS = {"repository", "ref", "workflow", "workflow_sha256", "job", "ok_lines", "log_required", "log_forbidden"}
PREFIX_ENTRY_KEYS = ENTRY_KEYS - {"ref"} | {"ref_prefix"}  # rp-1: exactly one of ref / ref_prefix
EXPIRY_S = 86400
FUTURE_S = 60


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def strict_load(path, limit=16384):
    with open(path, "rb") as f:
        raw = f.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("larger than %d bytes" % limit)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=fh_input.no_dupes)


def allowlist(packet):
    d = strict_load(os.path.join(packet, "ALLOWLIST.json"), 65536)
    if d.get("schema") != "FH_QUEUE_ALLOWLIST_1" or not isinstance(d.get("entries"), list):
        raise ValueError("allowlist schema")
    out = {}
    for e in d["entries"]:
        if not isinstance(e, dict) or set(e) not in (ENTRY_KEYS, PREFIX_ENTRY_KEYS):
            raise ValueError("allowlist entry keys")
        if "ref_prefix" in e:
            # rp-1: "<branch>/" (2-60 chars); its body without the final "/" must itself pass fh_input's ref rules.
            p = e["ref_prefix"]
            if not isinstance(p, str) or not 2 <= len(p) <= 60 or not p.endswith("/") or p.startswith("refs/"):
                raise ValueError("allowlist ref_prefix")
            body, slot = p[:-1], ("ref_prefix", p)
        else:
            body = slot = e["ref"]
        # Each entry must itself be a valid FH_LANE_INPUT_1 once a commit and expiry are added.
        fh_input_check(concrete(e, body, commit="0" * 40, expiry_epoch=2_000_000_000))
        k = (e["repository"], slot, e["workflow"], e["job"])
        if k in out:
            raise ValueError("duplicate allowlist entry")
        out[k] = e
    # rp-1 overlap: within one (repository, workflow, job) a prefix may not cover an exact ref or another prefix.
    for (repo, slot, wf, job) in out:
        if isinstance(slot, tuple):
            for (repo2, slot2, wf2, job2) in out:
                other = slot2[1] if isinstance(slot2, tuple) else slot2
                if (repo2, wf2, job2) == (repo, wf, job) and slot2 != slot and other.startswith(slot[1]):
                    raise ValueError("allowlist overlap: %r covers %r (%s %s %s)" % (slot[1], other, repo, wf, job))
    return out


def concrete(e, ref, **kw):
    # The FH_LANE_INPUT_1 fields of entry e with one concrete ref (ref / ref_prefix of the entry never copied).
    d = {k: v for k, v in e.items() if k not in ("ref", "ref_prefix")}
    return dict(d, ref=ref, schema="FH_LANE_INPUT_1", **kw)


def match(al, k):
    # rp-1: exact entry first (unchanged); else the single prefix entry of the same (repository, workflow, job) that
    # the concrete ref extends by at least one character. The concrete ref is then checked by fh_input as a full INPUT.
    if not all(isinstance(v, str) for v in k):
        raise ValueError("not allowlisted: %r" % (k,))
    if k in al:
        return al[k]
    repo, ref, wf, job = k
    hits = [e for (r2, s2, w2, j2), e in al.items() if isinstance(s2, tuple) and (r2, w2, j2) == (repo, wf, job)
            and ref.startswith(s2[1]) and len(ref) > len(s2[1])]
    if len(hits) != 1:
        raise ValueError("not allowlisted: %r" % (k,))
    if ".." in ref or "/." in ref or "//" in ref or ref.endswith(".lock"):  # also refused by fh_input below
        raise ValueError("ref under prefix: %r" % ref)
    fh_input_check(concrete(hits[0], ref, commit="0" * 40, expiry_epoch=2_000_000_000))
    return hits[0]


def fh_input_check(d):
    p = "/proc/self/fd/%d"
    r, w = os.pipe()
    os.write(w, json.dumps(d).encode())
    os.close(w)
    try:
        fh_input.load(p % r)
    finally:
        os.close(r)


def cmd_authority(active, packet):
    a = strict_load(active)
    if set(a) != {"schema", "packet_dir", "packet_sums_sha256", "allowlist_sha256", "activated_utc", "basis"}:
        raise ValueError("ACTIVE.json keys")
    if a["schema"] != "FH_QUEUE_ACTIVE_1" or os.path.realpath(packet) != a["packet_dir"] or os.path.islink(packet):
        raise ValueError("ACTIVE.json does not bind this exact packet path")
    if sha(os.path.join(packet, "SHA256SUMS")) != a["packet_sums_sha256"]:
        raise ValueError("packet SHA256SUMS hash differs from ACTIVE.json")
    if sha(os.path.join(packet, "ALLOWLIST.json")) != a["allowlist_sha256"]:
        raise ValueError("ALLOWLIST.json hash differs from ACTIVE.json")
    if subprocess.run(["sha256sum", "--quiet", "--strict", "-c", "SHA256SUMS"], cwd=packet).returncode != 0:
        raise ValueError("packet file hash mismatch")
    allowlist(packet)
    return 0


def reject(qd, name, why):
    os.makedirs(os.path.join(qd, "rejected"), mode=0o700, exist_ok=True)
    dst = os.path.join(qd, "rejected", name)
    if os.path.exists(dst):
        dst += ".%d" % time.time_ns()
    os.rename(os.path.join(qd, "requests", name), dst)
    with open(dst + ".why", "x") as f:
        f.write(why + "\n")


class Stale(Exception):
    pass


def enqueue_epoch(name):
    t = time.strptime(name[:16], "%Y%m%dT%H%M%SZ")
    return calendar.timegm(t)


def validate_request(path, name, al):
    if not name.endswith(".json") or not ID.fullmatch(name[:-5]) or os.path.islink(path) or not os.path.isfile(path):
        raise ValueError("request file name must be <UTC>-<label>.json, a regular file")
    enq = enqueue_epoch(name)
    now = int(time.time())
    if enq > now + FUTURE_S:
        raise ValueError("enqueue time in the future")
    if now >= enq + EXPIRY_S:
        raise Stale("NOT_RUN: enqueued %s, 24 h or older" % name[:16])
    r = strict_load(path, 4096)
    if not isinstance(r, dict) or not set(r) <= REQ_KEYS or r.get("schema") != "FH_QUEUE_REQUEST_1":
        raise ValueError("request keys/schema")
    e = match(al, (r.get("repository"), r.get("ref"), r.get("workflow"), r.get("job")))
    if not isinstance(r.get("requested_by"), str) or not WHO.fullmatch(r["requested_by"]):
        raise ValueError("requested_by")
    if "commit" in r and not (isinstance(r["commit"], str) and re.fullmatch(r"[0-9a-f]{40}", r["commit"])):
        raise ValueError("commit")
    note = r.get("note", "")
    if not isinstance(note, str) or len(note) > 200 or not all(0x20 <= ord(c) < 0x7F for c in note):
        raise ValueError("note")
    return r, e


def cmd_select(qd, packet):
    al = allowlist(packet)
    rq = os.path.join(qd, "requests")
    for name in sorted(os.listdir(rq)):
        path = os.path.join(rq, name)
        if os.path.exists(os.path.join(qd, "claimed", name)):
            reject(qd, name, "duplicate id: already claimed (each id runs at most once)")
            continue
        try:
            validate_request(path, name, al)
        except Stale as e:
            reject(qd, name, str(e))
            continue
        except (ValueError, UnicodeDecodeError) as e:   # an OSError (read error) is unknown: it reaches main(),
            reject(qd, name, "invalid: %s" % e)        # returns 1 and the queue suspends; the request is kept
            continue
        print(path)
        return 0
    return 3


def live_head(repo, ref):
    out = subprocess.run(["timeout", "-k", "2", "20", "gh", "api", "repos/@@FH_OWNER@@/%s/git/ref/heads/%s" % (repo, ref),
                          "--jq", ".object.sha"], capture_output=True, text=True)
    h = out.stdout.strip()
    if out.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", h):
        raise ValueError("live ref head unreadable")
    return h


def cmd_stage(path, ind, packet):
    qd = os.path.dirname(os.path.dirname(path))
    name = os.path.basename(path)
    try:
        r, e = validate_request(path, name, allowlist(packet))
    except Stale as x:
        reject(qd, name, str(x))
        return 3
    for f in ("INPUT.json", "INPUT.sha256"):
        if os.path.lexists(os.path.join(ind, f)):
            raise ValueError("%s already staged in %s" % (f, ind))
    head = live_head(r["repository"], r["ref"])
    if "commit" in r and r["commit"] != head:
        reject(qd, name, "stale: requested %s, live head %s" % (r["commit"], head))
        return 3
    # rp-1: the INPUT ref is always the request's concrete ref (equal to e["ref"] for an exact entry, so exact-entry
    # INPUT bytes are unchanged); a ref_prefix key never reaches INPUT.json.
    d = concrete(e, r["ref"], commit=head, expiry_epoch=enqueue_epoch(name) + EXPIRY_S,
                 note="lane-09 queue request %s by %s%s" % (name[:-5], r["requested_by"],
                                                             (": " + r["note"]) if r.get("note") else ""))
    raw = (json.dumps(d, indent=1, sort_keys=True) + "\n").encode()
    fh_input_check(d)
    # Intent first: the request moves to claimed/ (never requeued) before anything is staged for the launcher.
    os.makedirs(os.path.join(qd, "claimed"), mode=0o700, exist_ok=True)
    os.rename(path, os.path.join(qd, "claimed", name))
    with open(os.path.join(qd, "claimed", name[:-5] + ".input.json"), "xb") as f:
        f.write(raw)
    for f, data in (("INPUT.json", raw), ("INPUT.sha256", (hashlib.sha256(raw).hexdigest() + "\n").encode())):
        fd = os.open(os.path.join(ind, f), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as fo:
            fo.write(data)
    print(name[:-5])
    return 0


def cmd_record(qd, rid, rc, stdout_path):
    if not ID.fullmatch(rid) or not re.fullmatch(r"[0-9]{1,3}", rc):
        raise ValueError("record arguments")
    rc = int(rc)
    with open(stdout_path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    m = re.search(r"manifest_sha256=([0-9a-f]{64}) supervisor_exit=([0-9]+) evidence=(@@FH_EVIDENCE_ROOT@@/"
                  r"fh-b3-[0-9TZ]+)\s*$", text)
    # Clean terminal: the launcher refused with no effect (30), or it reached SEALED and the supervisor exit is a pass
    # (0) or an episode verdict (10-18). Anything else (31-35, 19, 20, signals, unknown) suspends the queue.
    clean = rc == 30 or (m is not None and int(m.group(2)) == rc and (rc == 0 or 10 <= rc <= 18))
    rec = {"schema": "FH_QUEUE_DONE_1", "id": rid, "launcher_exit": rc, "clean_terminal": clean,
           "evidence": m.group(3) if m else None, "manifest_sha256": m.group(1) if m else None,
           "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    write_done(qd, rid, rec)
    return 0 if clean else 1


def write_done(qd, rid, rec):
    os.makedirs(os.path.join(qd, "done"), mode=0o700, exist_ok=True)
    with open(os.path.join(qd, "done", rid + ".json"), "x") as f:
        json.dump(rec, f, indent=1, sort_keys=True)


def cmd_notrun(qd, rid, reason):
    if not ID.fullmatch(rid) or reason not in ("stop-requested", "thermal-at-launch", "lock-taken", "setup-failed",
                                              "hold-present", "hold-unknown"):  # lane-27 H26-2
        raise ValueError("notrun arguments")
    rec = {"schema": "FH_QUEUE_DONE_1", "id": rid, "launcher_exit": None, "clean_terminal": True,
           "not_run": reason, "evidence": None, "manifest_sha256": None,
           "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    write_done(qd, rid, rec)
    return 0


def main(a):
    try:
        if len(a) == 3 and a[0] == "authority":
            return cmd_authority(a[1], a[2])
        if len(a) == 3 and a[0] == "select":
            return cmd_select(a[1], a[2])
        if len(a) == 4 and a[0] == "stage":
            return cmd_stage(a[1], a[2], a[3])
        if len(a) == 5 and a[0] == "record":
            return cmd_record(a[1], a[2], a[3], a[4])
        if len(a) == 4 and a[0] == "notrun":
            return cmd_notrun(a[1], a[2], a[3])
    except (OSError, ValueError, UnicodeDecodeError) as e:
        print("fh_queue: %s" % e, file=sys.stderr)
        return 1
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
