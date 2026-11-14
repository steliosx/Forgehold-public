#!/usr/bin/python3 -I

# Validates FH_LANE_INPUT_1 and prints single validated fields. Every field is restricted to a charset that is safe
# to hold in a shell variable and to place in a GitHub API path; anything else is rejected (exit 1).
#   fh_input.py check <file>          -> exit 0 if the whole input is valid, else 1 (reason on stderr)
#   fh_input.py get <file> <field>    -> prints one validated scalar field (repository, workflow, workflow_sha256,
#                                        job, ref, commit, ok_lines, expiry_epoch)
#   fh_input.py logcheck <file> <log> -> prints a JSON object of log attribution checks (fixed-string matching only)
import json
import re
import sys

FIELDS = {
    "repository": re.compile(r"[A-Za-z0-9_.-]{1,100}"),
    "workflow": re.compile(r"[A-Za-z0-9_.-]{1,100}\.ya?ml"),
    "workflow_sha256": re.compile(r"[0-9a-f]{64}"),
    "job": re.compile(r"[A-Za-z0-9_-]{1,64}"),

    # git/ref/heads/<ref>. Path-safe segments; refs/*, "..", leading "-"/".", ".lock" and empty segments are rejected.
    "ref": re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*"),
    "commit": re.compile(r"[0-9a-f]{40}"),
}
ALLOWED = set(FIELDS) | {"schema", "log_required", "log_forbidden", "ok_lines", "expiry_epoch", "note"}


MAX_BYTES = 16384


def no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate JSON key")
    return dict(pairs)


def load(path):
    with open(path, "rb") as f:
        raw = f.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("input larger than 16384 bytes")
    d = json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes)
    if not isinstance(d, dict):
        raise ValueError("not an object")
    extra = set(d) - ALLOWED
    if extra:
        raise ValueError(f"unknown fields {sorted(extra)}")
    if d.get("schema") != "FH_LANE_INPUT_1":
        raise ValueError("schema")
    for k, rx in FIELDS.items():
        v = d.get(k)
        if not isinstance(v, str) or not rx.fullmatch(v):
            raise ValueError(f"field {k}")
    if d["repository"] in (".", ".."):
        raise ValueError("field repository")
    ref = d["ref"]
    # git refuses a path part that ends in ".lock" anywhere in the ref (not only at its end), a part that starts
    # with "." ("/." here; a leading "." is already refused by FIELDS), and a ref whose whole name ends in ".".
    # An interior part may end in "." (git check-ref-format accepts review/x./y).
    if (len(ref) > 100 or ".." in ref or ref.startswith("refs/") or "/." in ref
            or re.search(r"\.lock(/|$)", ref) or ref.endswith(".")):
        raise ValueError("field ref")
    for k in ("log_required", "log_forbidden"):
        v = d.get(k, [])
        if not isinstance(v, list) or len(v) > 16:
            raise ValueError(f"field {k}")
        for s in v:
            if not isinstance(s, str) or not (1 <= len(s) <= 200) or not all(0x20 <= ord(c) < 0x7f for c in s):
                raise ValueError(f"field {k} entry")
    ok = d.get("ok_lines")
    if not isinstance(ok, int) or isinstance(ok, bool) or not (0 <= ok <= 64):
        raise ValueError("field ok_lines")
    ex = d.get("expiry_epoch")
    if not isinstance(ex, int) or isinstance(ex, bool) or not (1_700_000_000 <= ex <= 4_000_000_000):
        raise ValueError("field expiry_epoch")
    note = d.get("note", "")
    if not isinstance(note, str) or len(note) > 500:
        raise ValueError("field note")
    return d


def logcheck(d, text):
    req = d.get("log_required", [])
    forb = d.get("log_forbidden", [])
    ok_count = len(re.findall(r"(?m)(?:^|\s)OK\s*$", text)) if text is not None else -1
    return {
        "log_present": text is not None,
        "log_required_all_present": text is not None and all(s in text for s in req),
        "log_forbidden_none_present": text is not None and not any(s in text for s in forb),
        "ok_lines_equal": ok_count == d["ok_lines"],
        "ok_lines_seen": ok_count,
    }


def main(a):
    try:
        if len(a) == 2 and a[0] == "check":
            load(a[1])
            return 0
        if len(a) == 3 and a[0] == "get":
            d = load(a[1])
            if a[2] not in set(FIELDS) | {"ok_lines", "expiry_epoch"}:
                return 1
            print(d[a[2]])
            return 0
        if len(a) == 3 and a[0] == "logcheck":
            d = load(a[1])
            try:
                with open(a[2], encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                text = None
            print(json.dumps(logcheck(d, text), sort_keys=True))
            return 0
    except (OSError, ValueError, UnicodeDecodeError) as e:
        print(f"fh_input: {e}", file=sys.stderr)
        return 1
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
