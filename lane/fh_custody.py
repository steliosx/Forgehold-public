#!/usr/bin/python3.14 -I

# Every write here is: open (no-overwrite where stated) -> full write -> fsync(file) -> close -> fsync(parent dir)
# -> readback compare. That is the strongest primitive this host offers without new infrastructure; it is NOT a
# proof of persistence across power loss or storage faults (stated qualification). Any failed step prints one
# line `FAIL <step> <detail>` on stderr and exits non-zero; callers treat that as the classification named below.
#

# existing non-symlink directory, and the leaf is opened O_NOFOLLOW / created O_EXCL. Ancestors above the parent are
# NOT checked; another process of this uid could still change them. No claim beyond that.
# Commands (all paths absolute):
#   reserve <E> <C> <hold-name> <hold-text-file>
#                                      mkdir E (0700, must not exist); C (0700) is created if missing, else must be

#                                      C/<hold-name> (0600, O_EXCL). exit 0 ok; 10 = refused before any effect;
#                                      11 = CUSTODY_FAILURE after a partial reservation (kept, never cleaned).
#   new <file> <text-file>             create file O_EXCL (0600) with text; exit 0 / 12 write failure.
#   append <file> <json-object>        append one JSON line (adds "t_utc"), O_APPEND; exit 0 / 13 failure.
#   seal <E> <manifest-name>           refuse symlinks/unsafe names under E; write <manifest-name> (O_EXCL, 0400)
#                                      listing every other regular file: path, bytes, sha256; then chmod 0400 all
#                                      listed files; print the manifest's own sha256 on stdout. exit 0 / 14.
import hashlib, json, os, stat, sys, time

def fail(code, step, detail):
    print(f"FAIL {step} {detail}", file=sys.stderr)
    sys.exit(code)

def fsync_dir(path, code):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as e:
        fail(code, "fsync-dir", f"{path}: {e}")

def checked_create(path, data, mode, code):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except OSError as e:
        fail(code, "create", f"{path}: {e}")
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fsync(fd)
    except OSError as e:
        fail(code, "write", f"{path}: {e}")
    finally:
        os.close(fd)
    fsync_dir(os.path.dirname(path), code)
    try:
        with open(path, "rb") as f:
            back = f.read()
    except OSError as e:
        fail(code, "readback", f"{path}: {e}")
    if back != data:
        fail(code, "readback", f"{path}: content differs")

def no_symlink_parent(path, code):
    parent = os.path.dirname(path)
    if os.path.islink(parent) or not os.path.isdir(parent):
        fail(code, "parent", f"{parent} missing or symlinked")

def cmd_reserve(e, c, hold_name, hold_text):
    if os.path.basename(hold_name) != hold_name or not hold_name.startswith("HOLD-"):
        fail(10, "reserve", "bad hold name")
    if os.path.lexists(e):
        fail(10, "reserve", f"{e} already exists")
    no_symlink_parent(e, 10)
    no_symlink_parent(c, 10)
    if os.path.lexists(c) and (os.path.islink(c) or not os.path.isdir(c)):
        fail(10, "reserve", f"{c} is not a plain directory")
    if os.path.lexists(os.path.join(c, hold_name)):
        fail(10, "reserve", f"{hold_name} already exists")
    data = open(hold_text, "rb").read()
    try:
        os.mkdir(e, 0o700)
    except OSError as x:
        fail(10, "mkdir", f"{e}: {x}")
    fsync_dir(os.path.dirname(e), 11)
    if not os.path.isdir(c):
        try:
            os.mkdir(c, 0o700)
        except OSError as x:
            fail(11, "mkdir", f"{c}: {x}")
        fsync_dir(os.path.dirname(c), 11)
    checked_create(os.path.join(c, hold_name), data, 0o600, 11)

def cmd_new(path, text_file):
    no_symlink_parent(path, 12)
    checked_create(path, open(text_file, "rb").read(), 0o600, 12)

def cmd_append(path, obj_json):
    no_symlink_parent(path, 13)
    try:
        obj = json.loads(obj_json)
        assert isinstance(obj, dict)
    except Exception as x:
        fail(13, "json", str(x))
    obj["t_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(line)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as x:
        fail(13, "append", f"{path}: {x}")
    fsync_dir(os.path.dirname(path), 13)
    with open(path, "rb") as f:
        if not f.read().endswith(line):
            fail(13, "readback", f"{path}: last line differs")

def cmd_seal(e, name):
    if os.path.basename(name) != name or name in ("", ".", "..") or not os.path.isabs(e) or os.path.islink(e) or not os.path.isdir(e):
        fail(14, "seal", "unsafe root or manifest name")
    rows = []
    for root, dirs, files in os.walk(e, followlinks=False):
        for d in dirs:
            if os.path.islink(os.path.join(root, d)):
                fail(14, "seal", f"symlinked dir {d}")
        for f in sorted(files):
            p = os.path.join(root, f)
            rel = os.path.relpath(p, e)
            if rel == name:
                fail(14, "seal", "manifest already exists")
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode) or "\n" in rel or rel.startswith(".."):
                fail(14, "seal", f"unsafe entry {rel!r}")
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                for b in iter(lambda: fh.read(1 << 20), b""):
                    h.update(b)
            rows.append({"path": rel, "bytes": st.st_size, "sha256": h.hexdigest()})
    rows.sort(key=lambda r: r["path"])
    data = (json.dumps({"schema": "FH_B3_MANIFEST_1", "files": rows}, indent=1, sort_keys=True) + "\n").encode()
    target = os.path.join(e, name)
    checked_create(target, data, 0o400, 14)
    # Lock, sync, then re-read every listed file: a changed byte after hashing fails the seal. chmod does not revoke
    # descriptors already open for writing; the wrapper's session-join witness runs before seal for that reason.
    for r in rows:
        q = os.path.join(e, r["path"])
        try:
            os.chmod(q, 0o400)
            fd = os.open(q, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
                h = hashlib.sha256()
                while True:
                    b = os.read(fd, 1 << 20)
                    if not b:
                        break
                    h.update(b)
                size = os.fstat(fd).st_size
            finally:
                os.close(fd)
        except OSError as x:
            fail(14, "lock", f"{r['path']}: {x}")
        if h.hexdigest() != r["sha256"] or size != r["bytes"]:
            fail(14, "reread", f"{r['path']}: changed after hashing")
    fsync_dir(e, 14)
    print(hashlib.sha256(data).hexdigest())

def main(a):
    if len(a) == 5 and a[0] == "reserve":
        cmd_reserve(a[1], a[2], a[3], a[4])
    elif len(a) == 3 and a[0] == "new":
        cmd_new(a[1], a[2])
    elif len(a) == 3 and a[0] == "append":
        cmd_append(a[1], a[2])
    elif len(a) == 3 and a[0] == "seal":
        cmd_seal(a[1], a[2])
    else:
        fail(2, "usage", " ".join(a))

if __name__ == "__main__":
    main(sys.argv[1:])
