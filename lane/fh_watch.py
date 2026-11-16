#!/usr/bin/python3 -I


# dispatches, stages, or touches VMs/engine/STOP/SUSPENDED/holds.
#   fh_watch.py <queue_dir> <packet_dir>                    one pass (forgehold-watch.timer, every 10 min)
#   fh_watch.py adopt <queue_dir> <packet_dir> <adopt.json>  W5 data-only initial adoption (no network)
# Exit: 0 = pass done (one request published and committed, or IDLE/PARKED/RECONCILED with nothing published);
#       2 = refusal, nothing published by this invocation; 3 = a request WAS published but its durability, the state
#       commit or the intent retirement was not established; the log line says exactly which step failed and whether
#       watch-intent.json is still present (while it is, every later pass reconciles it and enqueues nothing).
# Pass order (all local gates before any network): log + lock -> STOP/SUSPENDED/holds -> W1 preflight (stdlib only:
# ACTIVE.json binds packet path + SHA256SUMS hash + ALLOWLIST hash; every SHA256SUMS file hashed, regular, read-only)
# -> exec fh_input/fh_queue from those verified bytes -> fh_queue.cmd_authority -> WATCH.json from verified bytes ->
# W3 reconcile a retained intent -> W5 park unless every WATCH key was adopted -> W4 every done record that needs
# review has review evidence -> requests/ empty, nothing in flight -> W2 attended marker valid -> pick (gh head read,
# one per eligible entry, no retry) -> re-check all local gates -> durable intent -> link -> state commit -> unlink
# intent. One line per invocation in <queue_dir>/watch.log.
import calendar
import fcntl
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import time
import types
import zipfile

sys.dont_write_bytecode = True  # the packet dir is frozen; never write __pycache__ into it

WATCH_SCHEMA = "FH_QUEUE_WATCH_1"
STATE_SCHEMA = "FH_QUEUE_WATCH_STATE_2"
INTENT_SCHEMA = "FH_QUEUE_WATCH_INTENT_1"
ATTEND_SCHEMA = "FH_QUEUE_WATCH_ATTENDED_1"
REVIEW_SCHEMA = "FH_QUEUE_WATCH_REVIEWED_1"
ADOPT_SCHEMA = "FH_QUEUE_WATCH_ADOPT_1"
WATCH_TOP = {"schema", "entries", "window", "policy"}
WATCH_KEYS = {"repository", "ref", "workflow", "job", "mode"}
STATE_KEYS = {"last_head", "last_daily_utc_date", "last_request_id", "basis"}
BASES = ("adopted-record", "explicit-initial", "watcher")
INTENT_KEYS = {"schema", "request_id", "request_sha256", "repository", "ref", "workflow", "job", "mode", "head",
               "day", "attended_sha256", "temp"}
ATTEND_KEYS = {"schema", "operator", "packet_sums_sha256", "watch_sha256", "window", "start_line_utc",
               "start_line_ref", "from_utc", "until_utc"}
REVIEW_KEYS = {"schema", "id", "done_sha256", "review_message"}
ADOPT_KEYS = {"schema", "packet_sums_sha256", "watch_sha256", "entries"}
ADOPT_ENTRY_KEYS = {"repository", "ref", "workflow", "job", "from_request"}
ACTIVE_KEYS = {"schema", "packet_dir", "packet_sums_sha256", "allowlist_sha256", "activated_utc", "basis"}
MODES = ("new-commit", "daily")
MUST_BE_SUMMED = ("fh_watch.py", "WATCH.json", "fh_queue.py", "fh_input.py", "ALLOWLIST.json")
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
SUMLINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]{1,100})")
MSGID = re.compile(r"[0-9]{8}T[0-9]{6}Z-@@FH_REVIEWER_ID@@-[0-9a-f]{8}")
TEMP = re.compile(r"watch-req\.tmp-[0-9]{1,10}-[0-9]{1,25}")
WHO = "forgehold-watch"
MAILBOX = "@@FH_MAILBOX_DIR@@"

REVIEWER_KEY_ID = "@@FH_REVIEWER_KEY_ID@@"
REVIEWER_PUBKEY = "@@FH_REVIEWER_PUBKEY@@"
MAILBOX_SCHEMA = "agent-mailbox/1"
# W4r: the only accepted review evidence is an exact line in the signed body or a signed artifact. Any line containing
# the prefix must match REVIEW_LINE exactly, or the whole message is rejected as ambiguous.
REVIEW_PREFIX = "FH_RECORD_REVIEW_1"
REVIEW_LINE = re.compile(r"FH_RECORD_REVIEW_1 id=([0-9]{8}T[0-9]{6}Z-[a-z0-9-]{1,40}) done_sha256=([0-9a-f]{64}) "
                         r"disposition=([A-Z_]{1,32})")
REVIEW_OK = "REVIEWED"
ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
MAX_ZIP = 8 << 20
MAX_ENTRIES = 32
MAX_FILE = 1 << 20
# W2 bounds. MAX_ATTEND_S: an attended batch is at most 2 h, so a lapsed operator stops new enqueues within 2 h.
# MIN_REMAIN_S: 30 min must remain at enqueue: pacing margin for the queue's 300 s heads-up and a short run, NOT proof
# that the launch falls inside the window (host gates can wait longer). START_LINE_MAX_S: the batch start line was
# sent at most 1 h before the batch opened.
MAX_ATTEND_S = 7200
MIN_REMAIN_S = 1800
START_LINE_MAX_S = 3600
Q = None  # fh_queue, executed from verified bytes by load_verified()


class Refuse(Exception):
    pass


class Idle(Exception):
    pass


class Published(Exception):
    pass


class PostLink(Exception):
    # W3r: a step after the link failed. The message states exactly what is known (published, durable, state
    # committed, intent present or not); it never claims a marker exists that may be gone.
    pass


def no_dupes(pairs):
    # Identical to fh_input.no_dupes; needed before any packet code is loaded (W1).
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate JSON key")
    return dict(pairs)


def read_bounded(path, limit=MAX_FILE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError("%s is not a regular file" % path)
        raw = f.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("%s larger than %d bytes" % (path, limit))
    return raw


def jload(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def utc_stamp(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def utc_epoch(s):
    if not isinstance(s, str) or not UTC.fullmatch(s):
        raise ValueError("UTC time %r" % (s,))
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def skey(k):
    # No fh_input field charset admits a space, so this composite key is unambiguous.
    return " ".join(k)


def fsync_dir(d):
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw, made=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    if made is not None:
        made.append(path)  # listed only once this call has created the file; a pre-existing file is never listed
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def dumps(d):
    return (json.dumps(d, indent=1, sort_keys=True) + "\n").encode()


# ---- W1: integrity before import ---------------------------------------------------------------------------------

def preflight(qd, packet):
    # Stdlib only. Returns {name: verified bytes} for every SHA256SUMS file. Nothing from the packet runs before this.
    here = os.path.dirname(os.path.realpath(__file__))
    if not os.path.isabs(packet) or os.path.realpath(packet) != packet or packet != here:
        raise Refuse("fh_watch.py is not inside the named packet dir %r" % packet)
    st = os.lstat(packet)
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o222 or st.st_uid != os.getuid():
        raise Refuse("packet dir is not a read-only directory owned by this uid")
    try:
        a = jload(read_bounded(os.path.join(qd, "ACTIVE.json"), 16384))
    except (OSError, ValueError) as e:
        raise Refuse("ACTIVE.json unreadable: %s" % e)
    if not isinstance(a, dict) or set(a) != ACTIVE_KEYS or a["schema"] != "FH_QUEUE_ACTIVE_1":
        raise Refuse("ACTIVE.json keys/schema")
    if a["packet_dir"] != packet:
        raise Refuse("ACTIVE.json does not bind this exact packet path")
    sums = read_bounded(os.path.join(packet, "SHA256SUMS"), 65536)
    if sha(sums) != a["packet_sums_sha256"]:
        raise Refuse("packet SHA256SUMS hash differs from ACTIVE.json")
    listed = {}
    for line in sums.decode("ascii").split("\n")[:-1] if sums.endswith(b"\n") else [None]:
        m = SUMLINE.fullmatch(line) if line is not None else None
        if m is None or m.group(2) in listed or m.group(2) in (".", ".."):
            raise Refuse("SHA256SUMS line format/duplicate")
        listed[m.group(2)] = m.group(1)
    missing = [n for n in MUST_BE_SUMMED if n not in listed]
    if missing:
        raise Refuse("SHA256SUMS does not cover %s" % ", ".join(missing))
    if listed["ALLOWLIST.json"] != a["allowlist_sha256"]:
        raise Refuse("ALLOWLIST.json hash in SHA256SUMS differs from ACTIVE.json")
    extra = set(os.listdir(packet)) - set(listed) - {"SHA256SUMS"}
    if extra:
        raise Refuse("packet dir holds files outside SHA256SUMS: %s" % ", ".join(sorted(extra)))
    verified = {}
    for name, h in listed.items():
        p = os.path.join(packet, name)
        st = os.lstat(p)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o222 or st.st_uid != os.getuid() or st.st_nlink != 1:
            raise Refuse("%s is not a read-only regular file owned by this uid" % name)
        raw = read_bounded(p)
        if sha(raw) != h:
            raise Refuse("%s hash differs from SHA256SUMS" % name)
        verified[name] = raw
    return verified, a


def load_verified(packet, verified):
    # Execute fh_input then fh_queue from the bytes just hashed (no second disk read, no sys.path import). fh_queue's
    # own "import fh_input" resolves to the verified module already in sys.modules.
    global Q
    for name in ("fh_input", "fh_queue"):
        path = os.path.join(packet, name + ".py")
        mod = types.ModuleType(name)
        mod.__file__ = path
        sys.modules[name] = mod
        exec(compile(verified[name + ".py"], path, "exec"), mod.__dict__)
    Q = sys.modules["fh_queue"]
    while packet in sys.path:  # fh_queue inserts its dir; later lazy stdlib imports must not search the packet
        sys.path.remove(packet)
    if sys.modules.get("fh_input") is not Q.fh_input:
        raise Refuse("fh_queue did not bind the verified fh_input")


def watch_list(raw, al):
    d = jload(raw)
    if not isinstance(d, dict) or not set(d) <= WATCH_TOP or d.get("schema") != WATCH_SCHEMA:
        raise Refuse("WATCH.json keys/schema")
    if "policy" in d and not isinstance(d["policy"], str):
        raise Refuse("WATCH.json policy")
    w = d.get("window")
    if not isinstance(w, str) or not 1 <= len(w) <= 200 or not all(0x20 <= ord(c) < 0x7F for c in w):
        raise Refuse("WATCH.json window")
    es = d.get("entries")
    if not isinstance(es, list) or not 1 <= len(es) <= MAX_ENTRIES:
        raise Refuse("WATCH.json entries")
    out, seen = [], set()
    for e in es:
        if not isinstance(e, dict) or set(e) != WATCH_KEYS or not all(isinstance(v, str) for v in e.values()):
            raise Refuse("WATCH.json entry keys/types")
        if e["mode"] not in MODES:
            raise Refuse("WATCH.json mode %r" % e["mode"])
        k = (e["repository"], e["ref"], e["workflow"], e["job"])
        if k not in al:
            raise Refuse("WATCH.json entry not in ALLOWLIST.json: %r" % (k,))
        if k in seen:
            raise Refuse("WATCH.json duplicate entry: %r" % (k,))
        seen.add(k)
        out.append((k, e["mode"]))
    return out, w


class Ctx:
    pass


def bind(qd, packet):
    verified, a = preflight(qd, packet)
    load_verified(packet, verified)
    Q.cmd_authority(os.path.join(qd, "ACTIVE.json"), packet)  # unchanged queue check, incl. sha256sum -c
    c = Ctx()
    c.qd, c.packet = qd, packet
    c.al = Q.allowlist(packet)
    c.sums_sha = a["packet_sums_sha256"]
    c.watch_sha = sha(verified["WATCH.json"])
    c.watch, c.window = watch_list(verified["WATCH.json"], c.al)
    return c


# ---- local gates ---------------------------------------------------------------------------------------------------

def halted(qd):
    for m in ("STOP", "SUSPENDED"):
        if os.path.lexists(os.path.join(qd, m)):
            return "%s present" % m
    h = os.path.join(qd, "holds")
    # Same rule as queue_run.sh holds_state: holds/ missing, a symlink or not a directory is unknown, never clear.
    if os.path.islink(h) or not os.path.isdir(h):
        return "holds missing or not a plain directory (unknown is treated as a hold)"
    names = sorted(os.listdir(h))
    if names:
        return "hold present: holds/%s (%d total)" % (names[0], len(names))
    return None


def ids_in(d, allow_input):
    # Returns (ids, unexpected_name). claimed/ holds <id>.json and <id>.input.json; done/ holds <id>.json only.
    if not os.path.lexists(d):
        return set(), None
    out = set()
    for n in os.listdir(d):
        if allow_input and n.endswith(".input.json") and Q.ID.fullmatch(n[:-11]):
            continue
        if n.endswith(".json") and Q.ID.fullmatch(n[:-5]):
            out.add(n[:-5])
            continue
        return out, n
    return out, None


def busy(qd):
    names = os.listdir(os.path.join(qd, "requests"))  # missing requests/ = OSError = refusal
    if names:
        return "requests/ not empty (%d entries)" % len(names)
    claimed, odd = ids_in(os.path.join(qd, "claimed"), True)
    if odd is not None:
        return "unexpected name in claimed/: %r" % odd
    done, odd = ids_in(os.path.join(qd, "done"), False)
    if odd is not None:
        return "unexpected name in done/: %r" % odd
    flight = sorted(claimed - done)
    if flight:
        return "attempt in flight: claimed/%s.json has no done record" % flight[0]
    return None


# ---- W4: every done record that needs review --------------------------------------------------------------------

def minisign_verify(qd, env_raw, sig_raw):

    # needs files: the in-memory bytes go to a private 0700 temp dir in the queue dir, removed afterwards.
    d = os.path.join(qd, "watch-verify.tmp-%d-%d" % (os.getpid(), time.time_ns()))
    os.mkdir(d, 0o700)
    env, sig = os.path.join(d, "envelope.json"), os.path.join(d, "envelope.json.minisig")
    try:
        write_new(env, env_raw)
        write_new(sig, sig_raw)
        out = subprocess.run(["timeout", "-k", "2", "20", "minisign", "-V", "-P", REVIEWER_PUBKEY, "-m", env, "-x", sig],
                             capture_output=True, text=True)
    finally:
        for f in (env, sig):
            if os.path.lexists(f):
                os.unlink(f)
        os.rmdir(d)
    if out.returncode != 0:
        raise ValueError("signature does not verify against the configured reviewer key")
    comments = [ln.split(":", 1)[1].strip() for ln in out.stdout.splitlines() if ln.startswith("Trusted comment:")]
    if len(comments) != 1:
        raise ValueError("no single signed trusted comment")
    return comments[0]


def signed_message(qd, msg):
    # (envelope, {artifact name: bytes}) authenticated from the ORIGINAL message.zip kept by the mailbox, not from the
    # mutable cached envelope/artifacts/receipt. Raises ValueError (or OSError) with the reason.
    raw = read_bounded(os.path.join(MAILBOX, msg, "message.zip"), MAX_ZIP)
    members = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        infos = z.infolist()
        if len(infos) > 64 or len({i.filename for i in infos}) != len(infos):
            raise ValueError("member count/duplicates")
        for i in infos:
            n = i.filename
            if i.is_dir() or not (n in ("envelope.json", "envelope.json.minisig")
                                  or (n.startswith("artifacts/") and ARTIFACT_NAME.fullmatch(n[10:]))):
                raise ValueError("unexpected member %r" % n)
            with z.open(i) as f:
                b = f.read(MAX_FILE + 1)
            if len(b) > MAX_FILE:
                raise ValueError("member %r too large" % n)
            members[n] = b
    if "envelope.json" not in members or "envelope.json.minisig" not in members:
        raise ValueError("envelope or signature missing")
    if minisign_verify(qd, members["envelope.json"], members["envelope.json.minisig"]) != "%s %s" % (MAILBOX_SCHEMA,
                                                                                                     msg):
        raise ValueError("signed trusted comment does not name this message")
    env = jload(members["envelope.json"])
    if not isinstance(env, dict) or env.get("schema") != MAILBOX_SCHEMA or env.get("id") != msg \
            or env.get("from") != "@@FH_REVIEWER_ID@@" or env.get("to") != "@@FH_OPERATOR_ID@@" \
            or env.get("signer_key_id") != REVIEWER_KEY_ID or not isinstance(env.get("body"), str) \
            or not isinstance(env.get("artifacts"), list):
        raise ValueError("signed envelope fields")
    arts = {}
    for a in env["artifacts"]:
        if not isinstance(a, dict) or not isinstance(a.get("name"), str) or not ARTIFACT_NAME.fullmatch(a["name"]) \
                or a["name"] in arts or not isinstance(a.get("bytes"), int) or isinstance(a.get("bytes"), bool):
            raise ValueError("signed artifact entry")
        b = members.get("artifacts/" + a["name"])
        if b is None or len(b) != a["bytes"] or sha(b) != a.get("sha256"):
            raise ValueError("artifact %r differs from its signed size/sha256" % a["name"])
        arts[a["name"]] = b
    if {n for n in members if n.startswith("artifacts/")} != {"artifacts/" + n for n in arts}:
        raise ValueError("archive artifacts differ from the signed list")
    return env, arts


def review_lines(text, rid):
    # [(done_sha256, disposition)] for rid. Any line containing the prefix must be exactly well formed.
    out = []
    for line in text.split("\n"):
        line = line.rstrip("\r")
        if REVIEW_PREFIX not in line:
            continue
        m = REVIEW_LINE.fullmatch(line)
        if m is None:
            raise ValueError("malformed %s line" % REVIEW_PREFIX)
        if m.group(1) == rid:
            out.append((m.group(2), m.group(3)))
    return out


def review_evidence(qd, rid, done_sha):
    # None if reviewed, else the reason. W4r: positive, authenticated, exact-result evidence only. The local pointer
    # watch-reviewed/<id>.json names the message; the message itself (signature-verified original) must carry
    # "FH_RECORD_REVIEW_1 id=<rid> done_sha256=<current done sha> disposition=REVIEWED", and no other line for rid
    # (another hash or any other disposition = negative/ambiguous = not reviewed). A mention of the id is not evidence.
    # A review satisfies only this prerequisite: it authorizes no execution and clears no hold.
    p = os.path.join(qd, "watch-reviewed", rid + ".json")
    if not os.path.lexists(p):
        return "no watch-reviewed/%s.json" % rid
    try:
        r = jload(read_bounded(p, 4096))
    except (OSError, ValueError) as e:
        return "watch-reviewed/%s.json unreadable: %s" % (rid, e)
    if not isinstance(r, dict) or set(r) != REVIEW_KEYS or r["schema"] != REVIEW_SCHEMA or r["id"] != rid:
        return "watch-reviewed/%s.json keys/schema/id" % rid
    if r["done_sha256"] != done_sha:
        return "watch-reviewed/%s.json binds another done record (sha differs)" % rid
    msg = r["review_message"]
    if not isinstance(msg, str) or not MSGID.fullmatch(msg):
        return "watch-reviewed/%s.json review_message" % rid
    try:
        env, arts = signed_message(qd, msg)
        found = review_lines(env["body"], rid)
        for name in sorted(arts):
            found += review_lines(arts[name].decode("utf-8", "replace"), rid)
    except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as e:
        return "review message %s not authenticated evidence: %s" % (msg, e)
    if not found:
        return "review message %s has no %s line for %s" % (msg, REVIEW_PREFIX, rid)
    if any(f != (done_sha, REVIEW_OK) for f in found):
        return "review message %s is negative or ambiguous for %s (other hash or disposition)" % (msg, rid)
    return None


def unreviewed(qd):
    # Every done record, not only the newest: launcher_exit != 0 (null included) or clean_terminal != true needs
    # evidence. A later success never reviews an earlier failure. Corrupt done record = refusal.
    done, odd = ids_in(os.path.join(qd, "done"), False)
    if odd is not None:
        return "unexpected name in done/: %r" % odd
    for rid in sorted(done):
        try:
            raw = read_bounded(os.path.join(qd, "done", rid + ".json"), 4096)
            r = jload(raw)
        except (OSError, ValueError) as e:
            raise Refuse("done/%s.json unreadable: %s" % (rid, e))
        if not isinstance(r, dict) or r.get("schema") != "FH_QUEUE_DONE_1" or r.get("id") != rid:
            raise Refuse("done/%s.json schema/id" % rid)
        rc = r.get("launcher_exit")
        if rc is not None and (not isinstance(rc, int) or isinstance(rc, bool)):
            raise Refuse("done/%s.json launcher_exit" % rid)
        if rc != 0 or r.get("clean_terminal") is not True:
            why = review_evidence(qd, rid, sha(raw))
            if why:
                return "done %s launcher_exit=%s clean_terminal=%s not_run=%s unreviewed: %s" % (
                    rid, rc, r.get("clean_terminal"), r.get("not_run"), why)
    return None


# ---- W2: affirmative, bounded attended condition -----------------------------------------------------------------

def attended(c, now):
    # Returns (sha256 of the marker, None) when an enqueue is allowed now, else (None, reason). Malformed or scoped to
    # another packet/WATCH/window = Refuse (operator must see it).
    p = os.path.join(c.qd, "watch-attended.json")
    if not os.path.lexists(p):
        return None, "no watch-attended.json (no attended batch)"
    try:
        raw = read_bounded(p, 4096)
        d = jload(raw)
    except (OSError, ValueError) as e:
        raise Refuse("watch-attended.json unreadable: %s" % e)
    if not isinstance(d, dict) or set(d) != ATTEND_KEYS or d["schema"] != ATTEND_SCHEMA:
        raise Refuse("watch-attended.json keys/schema")
    if not isinstance(d["operator"], str) or not Q.WHO.fullmatch(d["operator"]):
        raise Refuse("watch-attended.json operator")
    ref = d["start_line_ref"]
    if not isinstance(ref, str) or not 1 <= len(ref) <= 200 or not all(0x20 <= ord(ch) < 0x7F for ch in ref):
        raise Refuse("watch-attended.json start_line_ref")
    if d["packet_sums_sha256"] != c.sums_sha or d["watch_sha256"] != c.watch_sha or d["window"] != c.window:
        raise Refuse("watch-attended.json is scoped to another packet/WATCH.json/window")
    try:
        s, f, u = utc_epoch(d["start_line_utc"]), utc_epoch(d["from_utc"]), utc_epoch(d["until_utc"])
    except ValueError as e:
        raise Refuse("watch-attended.json %s" % e)
    if not (f < u <= f + MAX_ATTEND_S) or not (f - START_LINE_MAX_S <= s <= f):
        raise Refuse("watch-attended.json bounds (span <= %d s; start line <= %d s before from)"
                     % (MAX_ATTEND_S, START_LINE_MAX_S))
    if now < f:
        return None, "attended batch not open until %s" % d["from_utc"]
    if now + MIN_REMAIN_S > u:
        return None, "attended batch ends %s (< %d s left)" % (d["until_utc"], MIN_REMAIN_S)
    return sha(raw), None


# ---- state (W5 adoption, W3 commits) ---------------------------------------------------------------------------

def load_state(qd):
    # None if absent (never adopted), else {skey: entry}. Corrupt = Refuse.
    p = os.path.join(qd, "watch-state.json")
    if not os.path.lexists(p):
        return None
    try:
        d = jload(read_bounded(p, 65536))
    except (OSError, ValueError) as e:
        raise Refuse("watch-state.json unreadable: %s" % e)
    if not isinstance(d, dict) or set(d) != {"schema", "keys"} or d["schema"] != STATE_SCHEMA \
            or not isinstance(d["keys"], dict):
        raise Refuse("watch-state.json keys/schema")
    for key, v in d["keys"].items():
        parts = key.split(" ")
        if len(parts) != 4 or not all(parts) or not isinstance(v, dict) or set(v) != STATE_KEYS:
            raise Refuse("watch-state.json entry %r" % key)
        h, dd, ri = v["last_head"], v["last_daily_utc_date"], v["last_request_id"]
        if v["basis"] not in BASES:
            raise Refuse("watch-state.json basis for %r" % key)
        if h is not None and not (isinstance(h, str) and HEX40.fullmatch(h)):
            raise Refuse("watch-state.json last_head for %r" % key)
        if dd is not None and not (isinstance(dd, str) and DATE.fullmatch(dd)):
            raise Refuse("watch-state.json last_daily_utc_date for %r" % key)
        if ri is not None and not (isinstance(ri, str) and Q.ID.fullmatch(ri)):
            raise Refuse("watch-state.json last_request_id for %r" % key)
        if (v["basis"] == "explicit-initial") != (h is None and ri is None and dd is None):
            raise Refuse("watch-state.json basis/history mismatch for %r" % key)
    return d["keys"]


def commit_state(qd, keys):
    p = os.path.join(qd, "watch-state.json")
    tmp = "%s.tmp-%d-%d" % (p, os.getpid(), time.time_ns())
    write_new(tmp, dumps({"schema": STATE_SCHEMA, "keys": keys}))
    try:
        os.rename(tmp, p)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    fsync_dir(qd)


# ---- W3: durable enqueue intent ----------------------------------------------------------------------------------

def load_intent(qd):
    p = os.path.join(qd, "watch-intent.json")
    if not os.path.lexists(p):
        return None
    try:
        d = jload(read_bounded(p, 4096))
    except (OSError, ValueError) as e:
        raise Refuse("watch-intent.json unreadable (intent retained): %s" % e)
    ok = isinstance(d, dict) and set(d) == INTENT_KEYS and d["schema"] == INTENT_SCHEMA \
        and isinstance(d["request_id"], str) and Q.ID.fullmatch(d["request_id"]) \
        and isinstance(d["request_sha256"], str) and HEX64.fullmatch(d["request_sha256"]) \
        and d["mode"] in MODES and isinstance(d["head"], str) and HEX40.fullmatch(d["head"]) \
        and isinstance(d["day"], str) and DATE.fullmatch(d["day"]) \
        and isinstance(d["attended_sha256"], str) and HEX64.fullmatch(d["attended_sha256"]) \
        and isinstance(d["temp"], str) and TEMP.fullmatch(d["temp"]) \
        and all(isinstance(d[f], str) for f in ("repository", "ref", "workflow", "job"))
    if not ok:
        raise Refuse("watch-intent.json fields (intent retained)")
    return d


def locate(qd, name):
    # Where the request with this exact name is now. Files only flow requests/ -> claimed/ | rejected/, so this
    # order is race-safe against a concurrent queue select/stage/reject. Returns (path or None).
    for d in ("requests", "claimed"):
        p = os.path.join(qd, d, name)
        if os.path.lexists(p):
            return p
    rj = os.path.join(qd, "rejected")
    if os.path.lexists(rj):
        for n in sorted(os.listdir(rj)):
            if n == name or (n.startswith(name + ".") and n[len(name) + 1:].isdigit()):
                return os.path.join(rj, n)
    return None


def state_entry(old, intent):
    e = dict(old or {"last_daily_utc_date": None})
    e.update(last_head=intent["head"], last_request_id=intent["request_id"], basis="watcher")
    if intent["mode"] == "daily":
        e["last_daily_utc_date"] = intent["day"]
    e.setdefault("last_daily_utc_date", None)
    return e


def durable_location(qd, intent):
    # W3r: make the observed request durable where it is now, before any state advance or intent retirement: fsync the
    # file and its directory, then confirm it is still there. If the queue moved it meanwhile (requests/ -> claimed/ |
    # rejected/), repeat at the new location (exact name + bytes). Raises PostLink if this cannot be established.
    name = intent["request_id"] + ".json"
    try:
        for _ in range(3):
            where = locate(qd, name)
            if where is None:
                raise PostLink("request %s not found while establishing durability" % name)
            if sha(read_bounded(where, 4096)) != intent["request_sha256"]:
                raise PostLink("%s bytes differ from the intent" % where[len(qd) + 1:])
            fd = os.open(where, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            fsync_dir(os.path.dirname(where))
            if os.path.lexists(where):
                return where[len(qd) + 1:]
    except (OSError, ValueError) as e:
        raise PostLink("durability of request %s not established: %s" % (name, e))
    raise PostLink("request %s moved repeatedly; durability not established" % name)


def finish_intent(qd, intent, state):
    # Post-link: state from the intent, then retire the temp and the intent. Each failure raises PostLink stating
    # exactly what is known at that point. Caller must have called durable_location first.
    k = (intent["repository"], intent["ref"], intent["workflow"], intent["job"])
    keys = dict(state or {})
    keys[skey(k)] = state_entry(keys.get(skey(k)), intent)
    try:
        commit_state(qd, keys)
    except OSError as e:
        raise PostLink("state commit not established (%s); watch-intent.json present" % e)
    t = os.path.join(qd, intent["temp"])
    try:
        if os.path.lexists(t):
            os.unlink(t)
    except OSError as e:
        raise PostLink("state committed; temp unlink failed (%s); watch-intent.json present" % e)
    try:
        os.unlink(os.path.join(qd, "watch-intent.json"))
    except OSError as e:
        raise PostLink("state committed; intent unlink failed (%s); watch-intent.json present" % e)
    try:
        fsync_dir(qd)
    except OSError as e:
        raise PostLink("state committed; watch-intent.json unlinked but the queue-dir fsync failed (%s): its removal "
                       "may not be durable; if it reappears a later pass reconciles it again (idempotent)" % e)


def retire_unpublished(qd, intent):
    # Never published: remove the temp and the intent, stating exactly what is known on failure.
    t = os.path.join(qd, intent["temp"])
    try:
        if os.path.lexists(t):
            os.unlink(t)
        os.unlink(os.path.join(qd, "watch-intent.json"))
    except OSError as e:
        present = os.path.lexists(os.path.join(qd, "watch-intent.json"))
        raise Refuse("intent %s not published; cleanup failed (%s); watch-intent.json %s"
                     % (intent["request_id"], e, "present" if present else "absent"))
    try:
        fsync_dir(qd)
    except OSError as e:
        raise Refuse("intent %s not published; intent unlinked but the queue-dir fsync failed (%s): if it reappears a "
                     "later pass reconciles it again" % (intent["request_id"], e))


def reconcile(c, intent):
    # Resolve a retained intent against the exact request identity. Never emits another request.
    qd = c.qd
    rid = intent["request_id"]
    name = rid + ".json"
    where = locate(qd, name)
    if where is not None:
        try:
            got = sha(read_bounded(where, 4096))
        except (OSError, ValueError) as e:
            raise Refuse("intent %s: %s unreadable (intent retained): %s" % (rid, where, e))
        if got != intent["request_sha256"]:
            raise Refuse("intent %s: %s bytes differ from the intent (intent retained)" % (rid, where))
        try:
            loc = durable_location(qd, intent)  # W3r: durable before state advance / intent retirement
            finish_intent(qd, intent, load_state(qd))
        except PostLink as e:
            raise Refuse("intent %s published: %s" % (rid, e))
        return "RECONCILED intent %s: published, durable at %s; state committed" % (rid, loc)
    if os.path.lexists(os.path.join(qd, "done", name)):
        raise Refuse("intent %s: done record without claimed request (intent retained)" % rid)
    retire_unpublished(qd, intent)
    return "RECONCILED intent %s: never published; intent removed, nothing enqueued" % rid


# ---- one pass ----------------------------------------------------------------------------------------------------

def label(k):
    slug = re.sub(r"[^a-z0-9]+", "-", ("%s-%s" % (k[3], k[0])).lower()).strip("-")
    return ("w-" + slug)[:40].rstrip("-") or "w"


def pick(c, state, today):
    notes = []
    for k, mode in c.watch:
        s = state[skey(k)]
        if mode == "daily" and s["last_daily_utc_date"] == today:
            continue  # no network call when today's daily request was already made
        try:
            head = Q.live_head(k[0], k[1])  # timeout -k 2 20 gh api ... --jq .object.sha; 40-hex or ValueError
        except (OSError, ValueError) as e:
            notes.append("skip %s: %s" % (skey(k), e))
            continue
        if mode == "new-commit" and head == s["last_head"]:
            continue
        return (k, mode, head), notes
    return None, notes


def local_gates(c):
    # Raises Idle with the reason; Refuse on corrupt queue records or marker. Returns the attended marker sha256.
    why = halted(c.qd) or unreviewed(c.qd) or busy(c.qd)
    if why:
        raise Idle(why)
    asha, why = attended(c, int(time.time()))
    if why:
        raise Idle(why)
    return asha


def enqueue(c, state, k, mode, head):
    qd = c.qd
    rid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + label(k)
    name = rid + ".json"
    if not Q.ID.fullmatch(rid):
        raise Refuse("generated id %r invalid" % rid)
    if locate(qd, name) or os.path.lexists(os.path.join(qd, "done", name)):
        raise Idle("id %s already exists (same-second collision)" % rid)
    raw = dumps({"schema": "FH_QUEUE_REQUEST_1", "repository": k[0], "ref": k[1], "workflow": k[2], "job": k[3],
                 "requested_by": WHO, "commit": head, "note": "auto %s" % mode})
    temp = "watch-req.tmp-%d-%d" % (os.getpid(), time.time_ns())  # queue dir root, no .json: never a request
    rtmp = os.path.join(qd, temp)
    ipath = os.path.join(qd, "watch-intent.json")
    made = []
    try:
        write_new(rtmp, raw, made)  # listed as soon as it is created, so a partial file is removed below
        Q.validate_request(rtmp, name, c.al)  # the exact check the queue applies at select, under the final name
        asha = local_gates(c)  # re-check every local gate: the gh calls may have taken ~66 s
        intent = {"schema": INTENT_SCHEMA, "request_id": rid, "request_sha256": sha(raw), "repository": k[0],
                  "ref": k[1], "workflow": k[2], "job": k[3], "mode": mode, "head": head,
                  "day": "%s-%s-%s" % (rid[0:4], rid[4:6], rid[6:8]), "attended_sha256": asha, "temp": temp}
        write_new(ipath, dumps(intent), made)  # durable recovery barrier; failure = no link
        fsync_dir(qd)
    except BaseException as e:
        for t in made:
            try:
                os.unlink(t)
            except OSError:
                pass
        if isinstance(e, (OSError, ValueError, Q.Stale)):
            raise Refuse("request not enqueued: %s" % e)
        raise
    try:
        os.link(rtmp, os.path.join(qd, "requests", name))  # EEXIST rather than replace; atomic appearance
    except OSError as e:
        if os.path.lexists(os.path.join(qd, "requests", name)):  # uncertain outcome: keep the intent, never guess
            raise Published("requests/%s present after a link error (%s); watch-intent.json present" % (name, e))
        # Not published: the intent is removed so it cannot be mistaken for one. If removal fails it stays and the
        # next pass reconciles it (locate finds nothing -> never published).
        for t in (rtmp, ipath):
            try:
                os.unlink(t)
            except OSError:
                pass
        raise Refuse("request not enqueued: link failed: %s" % e)
    msg = "ENQUEUE requests/%s %s mode=%s commit=%s attended=%s" % (name, skey(k), mode, head, asha[:16])
    try:
        durable_location(qd, intent)  # W3r: same barrier as reconcile (file + its current directory fsynced)
        finish_intent(qd, intent, state)
    except PostLink as e:
        raise Published("%s; POST-LINK STEP FAILED: %s" % (msg, e))
    return msg


def run(qd, packet):
    why = halted(qd)
    if why:
        return 0, "IDLE " + why
    c = bind(qd, packet)
    intent = load_intent(qd)
    if intent is not None:
        return 0, reconcile(c, intent)
    state = load_state(qd)
    missing = [skey(k) for k, _ in c.watch if state is None or skey(k) not in state]
    if missing:
        return 0, "PARKED initial adoption required (fh_watch.py adopt) for: %s" % "; ".join(missing)
    try:
        local_gates(c)
    except Idle as e:
        return 0, "IDLE %s" % e
    today = time.strftime("%Y-%m-%d", time.gmtime())
    chosen, notes = pick(c, state, today)
    tail = ("; " + "; ".join(notes)) if notes else ""
    if chosen is None:
        return 0, "IDLE no eligible watch entry" + tail
    try:
        return 0, enqueue(c, state, *chosen) + tail
    except Idle as e:
        return 0, "IDLE at re-check: %s; nothing enqueued%s" % (e, tail)


# ---- W5: explicit initial adoption (data only, no network) -------------------------------------------------------

def claimed_for(qd, k):
    # Newest claimed request id whose four fields equal k, or None.
    best = None
    cd = os.path.join(qd, "claimed")
    if not os.path.lexists(cd):
        return None
    for n in os.listdir(cd):
        if n.endswith(".input.json") or not n.endswith(".json") or not Q.ID.fullmatch(n[:-5]):
            continue
        r = jload(read_bounded(os.path.join(cd, n), 4096))
        if isinstance(r, dict) and (r.get("repository"), r.get("ref"), r.get("workflow"), r.get("job")) == k:
            if best is None or n[:-5] > best:
                best = n[:-5]
    return best


def quiescent_snapshot(qd):
    # W5r: adoption needs a coherent snapshot with no pending or in-flight request of any key: requests/ empty, every
    # claimed id has its done record, no unexpected names. Returns the exact listing for the before/after comparison.
    snap = []
    for d in ("requests", "claimed", "done", "rejected"):
        p = os.path.join(qd, d)
        snap.append((d, tuple(sorted(os.listdir(p))) if os.path.lexists(p) else None))
    if snap[0][1]:
        raise Refuse("adoption refused: requests/ is not empty (pending request history would be skipped or replayed)")
    claimed, odd = ids_in(os.path.join(qd, "claimed"), True)
    done, odd2 = ids_in(os.path.join(qd, "done"), False)
    if odd is not None or odd2 is not None:
        raise Refuse("adoption refused: unexpected name in claimed/ or done/")
    if claimed - done:
        raise Refuse("adoption refused: in flight: %s" % ", ".join(sorted(claimed - done)))
    return snap


def adopt(qd, packet, path):
    c = bind(qd, packet)
    if load_intent(qd) is not None:
        raise Refuse("watch-intent.json present: reconcile with a normal pass before adoption")
    snap = quiescent_snapshot(qd)
    state = load_state(qd) or {}
    try:
        d = jload(read_bounded(path, 65536))
    except (OSError, ValueError) as e:
        raise Refuse("adoption file unreadable: %s" % e)
    if not isinstance(d, dict) or set(d) != ADOPT_KEYS or d["schema"] != ADOPT_SCHEMA:
        raise Refuse("adoption keys/schema")
    if d["packet_sums_sha256"] != c.sums_sha or d["watch_sha256"] != c.watch_sha:
        raise Refuse("adoption file is scoped to another packet/WATCH.json")
    modes = {k: m for k, m in c.watch}
    want = {k for k in modes if skey(k) not in state}
    if not want:
        raise Refuse("nothing to adopt: every WATCH key is already in watch-state.json")
    es = d["entries"]
    if not isinstance(es, list):
        raise Refuse("adoption entries")
    new, seen = {}, set()
    for e in es:
        if not isinstance(e, dict) or set(e) != ADOPT_ENTRY_KEYS:
            raise Refuse("adoption entry keys")
        k = (e["repository"], e["ref"], e["workflow"], e["job"])
        if k not in want or k in seen:
            raise Refuse("adoption entry %r is not a missing WATCH key, or is repeated" % (k,))
        seen.add(k)
        newest = claimed_for(qd, k)
        fr = e["from_request"]
        if fr is None:
            if newest is not None:
                raise Refuse("%s has retained history (newest %s): adopt it, not explicit-initial" % (skey(k), newest))
            new[skey(k)] = {"last_head": None, "last_daily_utc_date": None, "last_request_id": None,
                            "basis": "explicit-initial"}
            continue
        if fr != newest:
            raise Refuse("%s: from_request %r is not the newest claimed record %r" % (skey(k), fr, newest))
        if not os.path.isfile(os.path.join(qd, "done", fr + ".json")):
            raise Refuse("%s: %s has no done record (in flight)" % (skey(k), fr))
        inp = jload(read_bounded(os.path.join(qd, "claimed", fr + ".input.json"), 16384))
        if not isinstance(inp, dict) or inp.get("schema") != "FH_LANE_INPUT_1" \
                or (inp.get("repository"), inp.get("ref"), inp.get("workflow"), inp.get("job")) != k \
                or not isinstance(inp.get("commit"), str) or not HEX40.fullmatch(inp["commit"]):
            raise Refuse("%s: claimed/%s.input.json does not bind this key and a commit" % (skey(k), fr))
        new[skey(k)] = {"last_head": inp["commit"], "last_request_id": fr, "basis": "adopted-record",
                        "last_daily_utc_date": ("%s-%s-%s" % (fr[0:4], fr[4:6], fr[6:8])) if modes[k] == "daily"
                        else None}
    if seen != want:
        raise Refuse("adoption must cover exactly the missing WATCH keys: %s"
                     % "; ".join(sorted(skey(k) for k in want - seen)))
    if quiescent_snapshot(qd) != snap:  # W5r: the baseline is committed only from one coherent, unchanged snapshot
        raise Refuse("adoption refused: queue records changed during adoption; nothing committed")
    keys = dict(state)
    keys.update(new)
    commit_state(qd, keys)
    return "ADOPTED %s" % "; ".join("%s <- %s" % (s, new[s]["last_request_id"] or "explicit-initial")
                                    for s in sorted(new))


# ---- entry -------------------------------------------------------------------------------------------------------

def main(a):
    if len(a) == 2:
        qd, packet, adopt_path = a[0], a[1], None
    elif len(a) == 4 and a[0] == "adopt":
        qd, packet, adopt_path = a[1], a[2], a[3]
    else:
        print("usage: fh_watch.py <queue_dir> <packet_dir> | adopt <queue_dir> <packet_dir> <adopt.json>",
              file=sys.stderr)
        return 2
    if not os.path.isabs(qd) or os.path.realpath(qd) != qd or not os.path.isdir(qd):
        print("fh_watch: queue dir must be an absolute real directory path", file=sys.stderr)
        return 2
    try:
        lfd = os.open(os.path.join(qd, "watch.log"), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        print("fh_watch: watch.log not writable: %s; refusing" % e, file=sys.stderr)
        return 2
    try:
        try:
            kfd = os.open(os.path.join(qd, "watch.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(kfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                rc, msg = (2 if adopt_path else 0), "IDLE another watcher invocation holds watch.lock"
            else:
                if adopt_path:
                    rc, msg = 0, adopt(qd, packet, adopt_path)
                else:
                    rc, msg = run(qd, packet)
        except Published as e:
            rc, msg = 3, "PUBLISHED %s" % e
        except Refuse as e:
            rc, msg = 2, "REFUSE %s" % e
        except Exception as e:  # any other failure before a link is a logged refusal (exit 2)
            rc, msg = 2, "REFUSE %s: %s" % (type(e).__name__, e)
        line = "%s %s\n" % (utc_stamp(), msg.replace("\n", " "))
        if rc:
            print("fh_watch: " + line, end="", file=sys.stderr)
        try:
            os.write(lfd, line.encode("utf-8", "replace"))
        except OSError as e:
            print("fh_watch: watch.log append failed: %s" % e, file=sys.stderr)
            rc = rc or 2
        return rc
    finally:
        os.close(lfd)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
