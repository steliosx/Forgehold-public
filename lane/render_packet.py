#!/usr/bin/python3 -I
"""Render a lane packet from this repository plus local deployment data (see docs/PACKET-FROM-PUBLIC.md).

Usage: render_packet.py <repository tree> <config directory> <new packet directory>

The config directory is deployment data and never part of this repository. It holds config.json
(schema FH_RENDER_CONFIG_1: one value per token), ALLOWLIST.json and WATCH.json. The packet directory
must not exist; its parent must exist and must not be inside a git work tree. The packet's own path and
name fill FH_PACKET_DIR and FH_PACKET_NAME.

Rendering removes each deployment file's guard (the refusal lines of a script, the comment and never-met
condition of a unit), replaces every @@FH_<NAME>@@ token, and writes every file read-only, then
SHA256SUMS and RENDER.json. It creates the packet directory itself (never replacing one), writes every
byte with a checked loop, reads every file back against the manifest, and only then sets the directory
read-only. The same inputs give the same bytes. Exit 0 = rendered and verified; 2 = refused: nothing of
this run is left, unless the message says the output was retained.
"""
import hashlib
import json
import os
import re
import subprocess
import sys

SCHEMA = "FH_RENDER_CONFIG_1"
RECORD_SCHEMA = "FH_RENDER_RECORD_1"
PATH = re.compile(r"/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
TYPES = {
    "path": PATH,
    "path_re": re.compile(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*"),  # also used inside a regex literal
    "path_list": re.compile(r"%s(?: %s){0,7}" % (PATH.pattern, PATH.pattern)),
    "sha256": re.compile(r"[0-9a-f]{64}"),
    "key_id": re.compile(r"[0-9A-F]{16}"),
    "pubkey": re.compile(r"RW[A-Za-z0-9+/]{54}"),
    "ident": re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"),
    "digits": re.compile(r"[1-9][0-9]{0,11}"),
    "label": re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:-]{0,79}"),
    "name": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}"),
}
TOKENS = {  # token -> type; FH_PACKET_DIR and FH_PACKET_NAME come from the packet directory itself
    "FH_PACKET_DIR": "path", "FH_PACKET_NAME": "name",
    "FH_QUEUE_DIR": "path", "FH_INPUT_DIR": "path", "FH_HOST_LOCK": "path", "FH_EVIDENCE_ROOT": "path_re",
    "FH_PILOT_DIR": "path", "FH_OPERATOR_HOME": "path", "FH_MAILBOX_DIR": "path", "FH_MARKER_FILE": "path",
    "FH_APP_KEY_FILE": "path", "FH_INPUT_ANCESTORS": "path_list", "FH_APP_KEY_ANCESTORS": "path_list",
    "FH_MARKER_SHA256": "sha256", "FH_PACK_NAME": "name", "FH_PACK_SHA256": "sha256",
    "FH_PIN_PRELOOP": "sha256", "FH_PIN_RUNNER": "sha256", "FH_PIN_REAL": "sha256", "FH_PIN_SMOLVM_BIN": "sha256",
    "FH_PIN_LIBKRUN": "sha256", "FH_PIN_LIBKRUNFW": "sha256", "FH_ENGINE_TOKEN_REF": "name",
    "FH_OWNER": "ident", "FH_REVIEWER_ID": "ident", "FH_OPERATOR_ID": "ident", "FH_OPERATOR_LABEL": "label",
    "FH_REVIEWER_KEY_ID": "key_id", "FH_REVIEWER_PUBKEY": "pubkey", "FH_APP_ID": "digits",
}
DERIVED = {"FH_PACKET_DIR", "FH_PACKET_NAME"}
TOKEN = re.compile(r"@@(FH_[A-Z0-9_]+)@@")
D = "examples/deployment/"
FILES = [  # packet file, source (None = copied from the config directory), kind; this is the SHA256SUMS order
    ("fh_custody.py", "lane/fh_custody.py", "py"), ("fh_hostscan.py", "lane/fh_hostscan.py", "py"),
    ("fh_input.py", "lane/fh_input.py", "py"), ("fh_queue.py", "lane/fh_queue.py", "py"),
    ("fh_workflow.py", "lane/fh_workflow.py", "py"),
    ("forgehold-lane-b3.service", D + "forgehold-lane-b3.service.example", "unit"),
    ("forgehold-lane-b3.socket", D + "forgehold-lane-b3.socket.example", "unit"),
    ("forgehold-queue.service", D + "forgehold-queue.service.example", "unit"),
    ("queue_run.sh", D + "queue_run.sh.example", "sh"), ("run_fh_b3.sh", D + "run_fh_b3.sh.example", "sh"),
    ("smolvm-gate-fh-b3.sh", D + "smolvm-gate-fh-b3.sh.example", "sh"),
    ("supervise_fh_b3.sh", D + "supervise_fh_b3.sh.example", "sh"),
    ("ALLOWLIST.json", None, "data"), ("fh_watch.py", "lane/fh_watch.py", "py"), ("WATCH.json", None, "data"),
    ("forgehold-watch.service", D + "forgehold-watch.service.example", "unit"),
    ("forgehold-watch.timer", D + "forgehold-watch.timer.example", "unit"),
]
SH_GUARD = ["# INACTIVE PUBLIC REFERENCE. Configure and review a separate deployment packet.",
            'printf "%s\\n" "Reference example only; execution is disabled." >&2', "exit 64"]
UNIT_GUARD = ("# INACTIVE PUBLIC REFERENCE; do not install. Paths, identities and pins are examples.",
              "ConditionPathExists=/nonexistent/forgehold-public-example-disabled")
MAX = 1 << 20


class Refused(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, limit=MAX):
    # O_NONBLOCK: a FIFO or device must not block the open; fstat then refuses anything but a regular file.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        st = os.fstat(fd)
        if not (st.st_mode & 0o170000 == 0o100000) or st.st_size > limit:
            raise Refused("not a bounded regular file: %s" % path)
        data = b""
        while len(data) <= limit:
            chunk = os.read(fd, 65536)
            if not chunk:
                return data
            data += chunk
        raise Refused("file too large: %s" % path)
    finally:
        os.close(fd)


def check_values(values):
    expected = set(TOKENS) - DERIVED
    if set(values) != expected:
        raise Refused("config values: missing %s, unknown %s" % (sorted(expected - set(values)), sorted(set(values) - expected)))
    for name, value in values.items():
        check_value(name, value)


def check_value(name, value):
    kind = TOKENS[name]
    ok = isinstance(value, str) and TYPES[kind].fullmatch(value) is not None
    if ok and kind in ("path", "path_re", "path_list"):
        ok = all(part not in (".", "..") for item in value.split(" ") for part in item.split("/")[1:])
    if not ok:
        raise Refused("value of %s is not a valid %s" % (name, kind))


def unguard(text, kind, source):
    lines = text.split("\n")
    if kind == "sh":
        if lines[1:4] != SH_GUARD:
            raise Refused("guard missing: %s" % source)
        del lines[1:4]
    elif kind == "unit":
        if len(lines) < 3 or (lines[0], lines[2]) != UNIT_GUARD:
            raise Refused("guard missing: %s" % source)
        del lines[2], lines[0]
    return "\n".join(lines)


def substitute(text, values, source):
    for name in TOKEN.findall(text):
        if name not in values:
            raise Refused("unknown token %s in %s" % (name, source))
    out = TOKEN.sub(lambda m: values[m.group(1)], text)
    if "@@" in out:
        raise Refused("token left in %s" % source)
    return out


def write_all(fd, data, ops):
    view = memoryview(data)
    while view:
        n = ops.write(fd, view)
        if not isinstance(n, int) or n <= 0 or n > len(view):
            raise Refused("write made no progress")
        view = view[n:]


def verify(out, rendered, ops):
    names = sorted(name for name, _ in rendered)
    if sorted(ops.listdir(out)) != names:
        raise Refused("packet directory inventory differs from the manifest")
    for name, data in rendered:
        fd = ops.open(os.path.join(out, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        try:
            st = ops.fstat(fd)
            if st.st_mode & 0o170000 != 0o100000 or st.st_mode & 0o7777 != 0o400 or st.st_size != len(data):
                raise Refused("written file differs from the manifest: %s" % name)
            got = b""
            while len(got) <= len(data):
                chunk = ops.read(fd, 65536)
                if not chunk:
                    break
                got += chunk
            if got != data:
                raise Refused("written file differs from the manifest: %s" % name)
        finally:
            ops.close(fd)


def publish(out, rendered, ops):
    """Create out (never replacing anything), write, verify, set 0500. On failure remove only what this run made."""
    try:
        ops.mkdir(out, 0o700)
    except FileExistsError:
        raise Refused("packet directory exists: %s" % out) from None
    made = []
    try:
        for name, data in rendered:
            path = os.path.join(out, name)
            fd = ops.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o400)
            made.append(path)
            try:
                write_all(fd, data, ops)
            finally:
                ops.close(fd)
            ops.chmod(path, 0o400)
        verify(out, rendered, ops)
        ops.chmod(out, 0o500)
        if ops.stat(out).st_mode & 0o7777 != 0o500:
            raise Refused("packet directory mode is not 0500")
    except BaseException as error:
        reason = error if isinstance(error, Refused) else "%s: %s" % (type(error).__name__, error)
        try:
            ops.chmod(out, 0o700)
            for path in made:
                try:
                    ops.unlink(path)
                except FileNotFoundError:
                    pass
            ops.rmdir(out)
        except OSError:
            raise Refused("%s; output retained at %s (it holds files this run did not make, or cleanup failed)"
                          % (reason, out)) from None
        if isinstance(error, (Refused, OSError)):
            raise Refused(str(reason)) from None
        raise


def source_commit(tree):
    try:
        head = subprocess.run(["git", "-C", tree, "rev-parse", "--verify", "HEAD"], capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if head.returncode != 0:
        return None
    dirty = subprocess.run(["git", "-C", tree, "status", "--porcelain", "--", "lane", "examples/deployment"],
                           capture_output=True, timeout=20)
    if dirty.returncode != 0 or dirty.stdout:
        raise Refused("repository tree has uncommitted changes under lane/ or examples/deployment/")
    return head.stdout.decode().strip()


def inside_git(path):
    while True:
        if os.path.lexists(os.path.join(path, ".git")):
            return True
        parent = os.path.dirname(path)
        if parent == path:
            return False
        path = parent


def data_files(cfgdir):
    allow, watch = read_regular(os.path.join(cfgdir, "ALLOWLIST.json")), read_regular(os.path.join(cfgdir, "WATCH.json"))
    try:
        a, w = json.loads(allow), json.loads(watch)
    except ValueError:
        raise Refused("ALLOWLIST.json or WATCH.json is not JSON") from None
    if not isinstance(a, dict) or not isinstance(a.get("entries"), list):
        raise Refused("ALLOWLIST.json has no entries list")
    if not isinstance(w, dict) or w.get("schema") != "FH_QUEUE_WATCH_1" or not isinstance(w.get("entries"), list):
        raise Refused("WATCH.json schema")
    keys = {(e.get("repository"), e.get("ref"), e.get("workflow"), e.get("job")) for e in a["entries"] if isinstance(e, dict)}
    for e in w["entries"]:
        if not isinstance(e, dict) or (e.get("repository"), e.get("ref"), e.get("workflow"), e.get("job")) not in keys:
            raise Refused("a WATCH.json entry is not in ALLOWLIST.json")
    return allow, watch


def render(tree, cfgdir, out, ops=os):
    out = os.path.abspath(out)
    parent, name = os.path.dirname(out), os.path.basename(out)
    if os.path.lexists(out):
        raise Refused("packet directory exists: %s" % out)
    if not os.path.isdir(parent) or os.path.islink(parent) or os.path.realpath(parent) != parent:
        raise Refused("packet parent is not a real directory: %s" % parent)
    if inside_git(parent):
        raise Refused("packet parent is inside a git work tree")
    cfg_raw = read_regular(os.path.join(cfgdir, "config.json"))
    try:
        cfg = json.loads(cfg_raw)
    except ValueError:
        raise Refused("config.json is not JSON") from None
    if not isinstance(cfg, dict) or set(cfg) != {"schema", "values"} or cfg["schema"] != SCHEMA \
            or not isinstance(cfg["values"], dict):
        raise Refused("config.json keys/schema")
    check_values(cfg["values"])
    values = dict(cfg["values"], FH_PACKET_DIR=out, FH_PACKET_NAME=name)
    for k in sorted(DERIVED):
        check_value(k, values[k])
    allow, watch = data_files(cfgdir)
    commit = source_commit(tree)
    rendered, sources = [], {}
    for pname, src, kind in FILES:
        if src is None:
            rendered.append((pname, allow if pname == "ALLOWLIST.json" else watch))
            continue
        raw = read_regular(os.path.join(tree, src))
        sources[src] = sha(raw)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise Refused("not UTF-8: %s" % src) from None
        rendered.append((pname, substitute(unguard(text, kind, src), values, src).encode("utf-8")))
    tool = read_regular(os.path.abspath(__file__))
    record = {"schema": RECORD_SCHEMA, "packet": name, "source_commit": commit, "sources": sources,
              "tool_sha256": sha(tool), "config_sha256": sha(cfg_raw), "allowlist_sha256": sha(allow),
              "watch_sha256": sha(watch), "tokens": sorted(TOKENS)}
    rendered.append(("RENDER.json", (json.dumps(record, indent=1, sort_keys=True) + "\n").encode()))
    sums = "".join("%s  %s\n" % (sha(data), pname) for pname, data in rendered).encode()
    publish(out, rendered + [("SHA256SUMS", sums)], ops)
    return record, sha(sums)


def main(argv):
    if len(argv) != 4:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    try:
        record, manifest = render(argv[1], argv[2], argv[3])
    except (Refused, OSError) as error:
        print("REFUSED: %s" % error, file=sys.stderr)
        return 2
    print("rendered %s (SHA256SUMS %s, source commit %s, config %s)" % (
        record["packet"], manifest, record["source_commit"], record["config_sha256"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
