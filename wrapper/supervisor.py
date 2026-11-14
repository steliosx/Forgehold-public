"""Bounded test supervisor: truthful receipt intent and preserved primary errors.

It grants nothing: the external observer declares a mock PASS only from the complete externally captured
receipt plus an independently observed, timely outer EXIT 0. The receipt itself never attests its own
capture: the serialised receipt_emission value is the pre-write intent 'prepared' (or 'short').

Standard library only (python -I safe_path). The four data primitives are restated from
cp_s1/data_rules.py (:8-14 Refused/require, :37-39 digest, :42-46 bounded canonical encode).
No Forgehold/R10 import; no controller, ledger, queue or authority layer.

Seams (keyword-only parameters of main() with the real defaults; the operator argv never reaches them):
popen, collect, open_pinned, read_once, sink_check, exists, now, writer. open_pinned/_read_once also take
`ops` (os-like: open/fstat/read/close) and `gate` (a callable that raises Refused when the applicable
original deadline no longer permits the next I/O action). Import has no side effect except reading the
monotonic clock once (ORIGIN; after interpreter bootstrap, recorded in the receipt).
"""
import fcntl
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time

ORIGIN = time.monotonic()

CHILD_CAP = 49152          # raw child stdout+stderr bytes, emitted once
SUPERVISOR_CAP = 16384     # framing, diagnostics, exception text, final receipt
AGGREGATE_CAP = 65536      # the one sink's total
BODY_SECONDS = 24          # body stop
FINAL_SECONDS = 27         # termination/finalizers complete; no kill/wait/close is started after it
ORCH_SECONDS = 28          # orchestration cutoff; no receipt write (or suffix) is started after it
WHOLE_SECONDS = 30         # separately approved outer ceiling (timeout binary), not enforced here
SEPARATOR = '-' * 70
RAN_LINE = re.compile(r'Ran ([0-9]+) tests in ([0-9]+\.[0-9]{3})s', re.ASCII)
RESULT_LINE = re.compile(r'(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok', re.ASCII)
MODE_TEXT = re.compile(r'[0-7]{4}', re.ASCII)
RECEIPT_SCHEMA = 'R60_SUPERVISOR_SUCCESSOR_RECEIPT_3'
STATUS_COMPLETE = 'MOCK_INTERNAL_CHECKS_COMPLETE'   # never 'PASS'
STATUS_REFUSED = 'REFUSED'
STATUS_UNKNOWN = 'UNKNOWN'
SECONDARY_STAGES = ('poll', 'kill', 'wait', 'forwarding', 'finalizers', 'clock', 'receipt', 'close')
BOUNDS = {'child_cap_bytes': CHILD_CAP, 'supervisor_cap_bytes': SUPERVISOR_CAP,
          'aggregate_cap_bytes': AGGREGATE_CAP, 'body_seconds': BODY_SECONDS,
          'final_seconds': FINAL_SECONDS, 'orchestration_seconds': ORCH_SECONDS,
          'whole_operation_seconds': WHOLE_SECONDS, 'invocations': 1, 'retry': False}


class Refused(RuntimeError):
    """An unmet predicate is non-PASS; never an authorization fallback (data_rules :8-9)."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(raw):
    require(type(raw) is bytes, 'bytes required')
    return hashlib.sha256(raw).hexdigest()


def encode(value, ceiling):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False,
                     ensure_ascii=True).encode('utf-8')
    require(0 < len(raw) <= ceiling, 'output bound')
    return raw


def hex64(value):
    require(type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value),
            'MISSING digest')
    return value


def literal_int(value, low, high):
    require(type(value) is int and low <= value <= high, 'literal integer bound')   # bool excluded
    return value


def _no_gate():
    return None


# ----------------------------------------------------------------------------- roster and grammar

class Roster:
    """Exact ordered full test IDs from the pinned roster spec; the only source of expectations."""

    def __init__(self, spec):
        require(type(spec) is dict, 'roster spec dict')
        module = spec.get('module')
        ids = spec.get('expected_full_ids')
        counts = spec.get('class_counts')
        count = spec.get('top_level_count')
        require(type(module) is str and module and type(ids) is list and type(counts) is dict
                and type(count) is int, 'roster spec fields')
        require(len(ids) == count and len(set(ids)) == count and count > 0, 'roster count/uniqueness')
        seen = {}
        previous = None
        for full in ids:
            require(type(full) is str and full.startswith(module + '.'), 'roster module prefix')
            parts = full[len(module) + 1:].split('.')
            require(len(parts) == 2 and all(parts) and parts[1].startswith('test_'), 'roster id shape')
            cls, method = parts
            seen[cls] = seen.get(cls, 0) + 1
            key = (cls, method)
            require(previous is None or key > previous, 'roster order: class then method')
            previous = key
        require(seen == counts and sum(counts.values()) == count, 'roster class counts')
        self.module = module
        self.ids = tuple(ids)
        self.count = count


def parse_terminal(raw, roster):
    """Fixed-shape classifier of the CPython 3.11+ `unittest -v` terminal; returns the ordered IDs."""
    require(type(raw) is bytes and 0 < len(raw) <= CHILD_CAP, 'child output bound')
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError as error:
        raise Refused('child output is not strict UTF-8') from error
    require(text.endswith('\n'), 'trailing newline required')
    lines = text[:-1].split('\n')
    require(len(lines) == roster.count + 5, 'terminal line count differs from roster shape')
    results, tail = lines[:roster.count], lines[roster.count:]
    require(tail[0] == '' and tail[1] == SEPARATOR and tail[3] == '' and tail[4] == 'OK',
            'terminal tail shape (blank, separator, summary, blank, OK) required')
    summary = RAN_LINE.fullmatch(tail[2])
    require(summary is not None, 'summary grammar')
    require(int(summary.group(1)) == roster.count, 'summary count differs from roster')
    outcomes = []
    for index, line in enumerate(results):
        match = RESULT_LINE.fullmatch(line)
        require(match is not None, 'unclassified or non-ok result line: ' + line[:80])
        name, full = match.group(1), match.group(2)
        require(full == roster.ids[index], 'outcome out of roster order or unexpected id')
        require(full.rsplit('.', 1)[1] == name and full.startswith(roster.module + '.'),
                'name/full-ID mismatch')
        outcomes.append(full)
    return tuple(outcomes)


# ----------------------------------------------------------------------------- budget, deadlines, finalizers

class Budget:
    """All bytes that reach the one sink pass through emit_*; counters are reserved BEFORE writing.

    A write acknowledgement must be a literal int with 0 < written <= len(remaining slice); a positive
    short write continues with the remaining suffix inside the same reserved attempt, but only while the
    caller's `gate` (the original applicable deadline) still permits the next write: the gate is called
    before EVERY writer call and after every acknowledged write. Anything else is an uncertain emission:
    Refused is raised, the reservation stays charged, and the caller must not restart or replace.
    """

    def __init__(self, writer):
        self.writer = writer
        self.child_bytes = 0
        self.supervisor_bytes = 0

    @property
    def total(self):
        return self.child_bytes + self.supervisor_bytes

    def _reserve(self, raw, current, cap, label):
        require(type(raw) is bytes, 'bytes required')
        require(current + len(raw) <= cap, label + ' output cap')
        require(self.total + len(raw) <= AGGREGATE_CAP, 'aggregate output cap')
        return len(raw)

    def _write(self, raw, gate):
        offset = 0
        while offset < len(raw):
            gate()                                                     # before each selected write
            remaining = raw[offset:]
            written = self.writer(remaining)
            require(type(written) is int and 0 < written <= len(remaining),
                    'uncertain sink write acknowledgement')
            offset += written
            gate()                                                     # after each acknowledged write

    def emit_child(self, raw, gate=_no_gate):
        self.child_bytes += self._reserve(raw, self.child_bytes, CHILD_CAP, 'child')
        self._write(raw, gate)

    def emit_supervisor(self, raw, gate=_no_gate):
        self.supervisor_bytes += self._reserve(raw, self.supervisor_bytes, SUPERVISOR_CAP, 'supervisor')
        self._write(raw, gate)

    def fits_supervisor(self, length):
        return (type(length) is int and length >= 0 and self.supervisor_bytes + length <= SUPERVISOR_CAP
                and self.total + length <= AGGREGATE_CAP)


class Deadlines:
    """One monotonic origin; absolute cutoffs; equality is late; checked before AND after each action.

    remaining() has NO floor; timeout() refuses when nothing remains; gate(stage, cutoff) returns a
    callable suitable for Budget/open_pinned that performs check() with that stage name.
    """

    def __init__(self, origin, now=time.monotonic):
        self.origin = origin
        self.now = now
        self.body = origin + BODY_SECONDS
        self.final = origin + FINAL_SECONDS
        self.orch = origin + ORCH_SECONDS
        self.late = []

    def check(self, stage, cutoff):
        moment = self.now()
        if moment >= cutoff:
            self.late.append({'stage': stage, 'late_by_seconds': round(moment - cutoff, 6)})
            raise Refused('deadline reached: ' + stage)
        return moment

    def before(self, cutoff):
        return self.now() < cutoff

    def remaining(self, cutoff):
        return cutoff - self.now()

    def timeout(self, cutoff, ceiling):
        remaining = self.remaining(cutoff)
        require(remaining > 0, 'no time remains for a blocking action')
        return min(ceiling, remaining)

    def gate(self, stage, cutoff):
        return lambda: self.check(stage, cutoff)


class Finalizers:
    """Independent once-only close attempts for every acquired handle; never raises; never retries.

    finalize_all(may_attempt, still_timely): may_attempt is evaluated immediately BEFORE each close (a
    handle whose turn comes after the deadline is `unattempted_due_to_deadline`); still_timely is
    evaluated immediately AFTER each close that returned: a close that returned after the deadline is
    `closed_late` (the one close did happen; it is recorded as an uncertainty, never retried). A failing
    predicate counts as not allowed / not timely.
    """

    def __init__(self):
        self.handles = {}
        self.outcomes = {}

    def acquire(self, name, handle, close=None):
        require(name not in self.handles, 'duplicate handle ownership: ' + name)
        self.handles[name] = (handle, close if close is not None else handle.close)
        self.outcomes[name] = 'acquired'

    def finalize(self, name):
        if name not in self.handles:
            self.outcomes[name] = self.outcomes.get(name, 'not_acquired')
            return self.outcomes[name]
        if self.outcomes[name] != 'acquired':
            return self.outcomes[name]          # already attempted or skipped: never a second close
        self.outcomes[name] = 'attempted'       # marked BEFORE the close
        _, close = self.handles[name]
        try:
            close()
        except BaseException as error:        # noqa: BLE001 - recorded, never re-raised, others still run
            self.outcomes[name] = 'failed:' + type(error).__name__
            return self.outcomes[name]
        self.outcomes[name] = 'closed'
        return self.outcomes[name]

    @staticmethod
    def _allowed(predicate):
        try:
            return bool(predicate())
        except BaseException:  # noqa: BLE001 - a failing clock is an uncertainty, not permission
            return False

    def finalize_all(self, may_attempt=lambda: True, still_timely=lambda: True):
        for name in list(self.handles):
            if self.outcomes[name] != 'acquired':
                continue
            if not self._allowed(may_attempt):
                self.outcomes[name] = 'unattempted_due_to_deadline'
                continue
            outcome = self.finalize(name)
            if outcome == 'closed' and not self._allowed(still_timely):
                self.outcomes[name] = 'closed_late'
        return dict(self.outcomes)


# ----------------------------------------------------------------------------- pins, scope, sink

def check_pin_row(row):
    """Literal field types: path absolute str, bytes non-bool int >= 0, mode four octal digits, sha256 hex64."""
    require(type(row) is dict and set(row) == {'path', 'bytes', 'mode', 'sha256'}, 'pin row schema')
    require(type(row['path']) is str and os.path.isabs(row['path']), 'pin path absolute str')
    literal_int(row['bytes'], 0, 2 ** 31 - 1)
    require(type(row['mode']) is str and MODE_TEXT.fullmatch(row['mode']) is not None, 'pin mode text')
    hex64(row['sha256'])
    return row


def _read_descriptor(fd, limit, ops, gate):
    """Read at most limit+1 bytes from an open descriptor, gated before and after each read call."""
    chunks = []
    got = 0
    while got <= limit:
        gate()
        chunk = ops.read(fd, limit + 1 - got)
        gate()
        if not chunk:
            break
        chunks.append(chunk)
        got += len(chunk)
    return b''.join(chunks)


def _with_descriptor(fd, body, ops, gate):
    """Run body(fd); then ONE close attempt. The first failure stays primary; a close failure after a
    primary is attached as `__secondary_close__` (bounded fact for the receipt), never replacing it. A
    close-only failure is raised itself. No retry, no swallowed error, no fabricated closure."""
    primary = None
    result = None
    try:
        result = body(fd)
    except BaseException as error:  # noqa: BLE001 - captured to be re-raised after the single close
        primary = error
    close_error = None
    try:
        gate()                                                         # before the selected close
        ops.close(fd)
    except BaseException as error:  # noqa: BLE001
        close_error = error
    else:
        try:
            gate()                                                     # adjacent check AFTER the successful close
        except BaseException as error:  # noqa: BLE001 - the one close happened; lateness is a refusal, never a second close
            close_error = error
    if primary is not None:
        if close_error is not None:
            try:
                primary.__secondary_close__ = {'type': type(close_error).__name__,
                                               'text': str(close_error)[:120]}
            except BaseException:  # noqa: BLE001 - an exception that refuses attributes still propagates
                pass
        raise primary
    if close_error is not None:
        raise close_error
    return result


def open_pinned(row, ops=os, gate=_no_gate):
    """Read a pinned regular file ONCE, validating the OPENED descriptor; return the exact checked bytes.

    Reads at most bytes + 1; refuses on excess, short read, size/mode/digest mismatch, non-regular file
    or a path that is not its own realpath. Callers parse exactly the returned bytes; no second open.
    """
    check_pin_row(row)
    path = row['path']
    require(os.path.realpath(path) == path, 'pin path is not its own realpath')
    gate()
    fd = ops.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))

    def body(fd):
        gate()                                                         # post-open check, inside the cleanup boundary
        s = ops.fstat(fd)
        gate()                                                         # adjacent check after stat
        require(stat.S_ISREG(s.st_mode), 'opened descriptor is not a regular file')
        require('%04o' % stat.S_IMODE(s.st_mode) == row['mode'], 'opened file mode differs from pin')
        require(s.st_size == row['bytes'], 'opened file size differs from pin')
        return _read_descriptor(fd, row['bytes'], ops, gate)
    raw = _with_descriptor(fd, body, ops, gate)
    require(len(raw) == row['bytes'], 'read length differs from pin')
    require(digest(raw) == row['sha256'], 'opened file digest differs from pin')
    return raw


def verify(row, open_pinned=open_pinned, gate=_no_gate):
    open_pinned(row, gate=gate)
    return dict(row)


def verify_rows(rows, deadlines, stage, cutoff, open_pinned=open_pinned):
    result = []
    for index, row in enumerate(rows):
        deadlines.check('%s[%d].before' % (stage, index), cutoff)
        result.append(verify(row, open_pinned, deadlines.gate('%s[%d].io' % (stage, index), cutoff)))
        deadlines.check('%s[%d].after' % (stage, index), cutoff)
    return result


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    require(len(keys) == len(set(keys)), 'duplicate scope JSON key')
    return dict(pairs)


def load_scope(raw):
    """The scope's bounds must EQUAL the constants in this module, value and type; they are not knobs.

    The other fields (argv, cwd, pins, marker) are shape-checked here only. Their values are bound by the
    outer packet, which pins the scope file's bytes; this function does not compare the scope to a digest.
    """
    scope = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_no_duplicate_keys)
    require(type(scope) is dict, 'scope dict')
    for key in ('argv', 'cwd', 'inputs', 'interpreter_pin', 'timeout_pin', 'roster_pin',
                'preserved', 'bounds', 'once_namespace_marker'):
        require(key in scope, 'scope field MISSING: ' + key)
    bounds = scope['bounds']
    require(type(bounds) is dict and set(bounds) == set(BOUNDS), 'scope bounds keys differ from fixed constants')
    for key, expected in BOUNDS.items():
        require(type(bounds[key]) is type(expected) and bounds[key] == expected,
                'scope bound differs from fixed constant: ' + key)
    argv = scope['argv']
    require(type(argv) is list and len(argv) >= 2 and all(type(a) is str and a for a in argv), 'argv shape')
    require(type(scope['cwd']) is str and os.path.isabs(scope['cwd']), 'cwd absolute')
    require(argv[0] == scope['interpreter_pin']['path'], 'argv interpreter differs from pin')
    require('-t' in argv and argv.index('-t') + 1 < len(argv) and argv[argv.index('-t') + 1] == scope['cwd'],
            'cwd must equal discover top-level')
    require(type(scope['once_namespace_marker']) is str and os.path.isabs(scope['once_namespace_marker']),
            'once namespace marker path')
    require(type(scope['inputs']) is list and type(scope['preserved']) is list, 'pin lists')
    for row in scope['inputs'] + [scope['interpreter_pin'], scope['timeout_pin'], scope['roster_pin']] + scope['preserved']:
        check_pin_row(row)
    return scope


def verify_sink(fstat=os.fstat, getfl=lambda fd: fcntl.fcntl(fd, fcntl.F_GETFL)):
    """fd 1 and fd 2 must be the same fresh, append-only regular file, bound before Python started.

    Necessary observations only: this does not enforce absence of truncation, replacement, other writers
    or an inherited hard cap; those are outer-operator bindings reviewed separately.
    """
    out, err = fstat(1), fstat(2)
    require(stat.S_ISREG(out.st_mode), 'stdout is not a regular file sink')
    require((out.st_dev, out.st_ino) == (err.st_dev, err.st_ino), 'stderr is not the same sink')
    require(out.st_size == 0, 'sink is not fresh')
    for fd in (1, 2):
        flags = getfl(fd)
        require(flags & os.O_APPEND, 'sink fd %d is not append-only' % fd)
        require((flags & os.O_ACCMODE) in (os.O_WRONLY, os.O_RDWR), 'sink fd %d not writable' % fd)
    return {'dev': out.st_dev, 'ino': out.st_ino}


# ----------------------------------------------------------------------------- child output collection

def collect_child_output(child, deadlines, finalizers, selector_factory=selectors.DefaultSelector,
                         read=os.read, set_blocking=os.set_blocking):
    """Bounded non-blocking read of the child's merged pipe until EOF; deadline-checked around each action.

    selector_factory/read/set_blocking are seams with the real defaults so definitions can model a late
    select return without patching module globals.
    """
    data = bytearray()
    finalizers.acquire('child_stdout', child.stdout)
    selector = selector_factory()
    finalizers.acquire('selector', selector)
    set_blocking(child.stdout.fileno(), False)
    selector.register(child.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            deadlines.check('select.before', deadlines.body)
            ready = selector.select(deadlines.timeout(deadlines.body, 0.1))
            deadlines.check('select.after', deadlines.body)              # a late select return starts no read
            for key, _ in ready:
                deadlines.check('read.before', deadlines.body)             # adjacent check per selected read
                try:
                    chunk = read(key.fileobj.fileno(), min(4096, CHILD_CAP - len(data) + 1))
                except BlockingIOError:
                    deadlines.check('read.after', deadlines.body)
                    continue
                # QA-1: bytes already read are kept (up to the cap) BEFORE the post-read checks, so a refusal at
                # read.after or at the cap still carries them; no further I/O starts after either refusal.
                permitted = chunk[:CHILD_CAP - len(data)]
                data.extend(permitted)
                deadlines.check('read.after', deadlines.body)
                if not chunk:
                    selector.unregister(key.fileobj)
                    deadlines.check('eof_close.before', deadlines.body)   # the EOF close is a selected action
                    finalizers.finalize('child_stdout')                  # recorded once-only close
                    deadlines.check('eof_close.after', deadlines.body)
                    continue
                require(len(permitted) == len(chunk), 'child output cap exceeded')
            deadlines.check('batch.after', deadlines.body)
    except BaseException as error:
        error.partial_child_output = bytes(data)   
        raise
    return bytes(data)


# ----------------------------------------------------------------------------- receipt helpers

def _record_error(receipt, stage, error, status):
    """Keep the FIRST failure as primary; later failures go to bounded secondary slots; status only worsens.

    A primary carrying `__secondary_close__` (from _with_descriptor) also fills the bounded 'close' slot.
    """
    try:
        text = str(error)[:240]
    except BaseException:  # noqa: BLE001 - an unprintable error must not escape the handler
        text = '<unprintable>'
    entry = {'type': type(error).__name__, 'text': text, 'stage': stage}
    if receipt.get('error') is None:
        receipt['error'] = entry
    elif stage in SECONDARY_STAGES and stage not in receipt['secondary']:
        receipt['secondary'][stage] = entry
    elif 'other' not in receipt['secondary']:
        receipt['secondary']['other'] = {'type': entry['type'], 'stage': stage, 'count': 1}
    else:
        receipt['secondary']['other']['count'] += 1
    close_fact = getattr(error, '__secondary_close__', None)
    if type(close_fact) is dict and 'close' not in receipt['secondary']:
        receipt['secondary']['close'] = dict(close_fact, stage='close')
    order = {STATUS_COMPLETE: 0, STATUS_REFUSED: 1, STATUS_UNKNOWN: 2}
    if order[status] > order[receipt['status']]:
        receipt['status'] = status


def _frame(budget, label, value, gate):
    budget.emit_supervisor(encode({'frame': label, 'value': value}, SUPERVISOR_CAP) + b'\n', gate)


# ----------------------------------------------------------------------------- main

def main(argv=None, *, now=time.monotonic, writer=None, popen=subprocess.Popen,
         collect=collect_child_output, open_pinned=open_pinned, sink_check=verify_sink,
         exists=os.path.exists, read_once=None):
    argv = sys.argv[1:] if argv is None else argv
    writer = (lambda raw: os.write(1, raw)) if writer is None else writer
    read_once = _read_once if read_once is None else read_once      # defined below main()
    deadlines = Deadlines(ORIGIN, now)
    budget = Budget(writer)
    finalizers = Finalizers()
    child = None
    data = b''
    emission = {'child': 'none', 'receipt': 'none'}                 # internal attempt states; never serialized
    receipt = {'schema': RECEIPT_SCHEMA, 'status': STATUS_COMPLETE, 'error': None, 'secondary': {},
               'child_invocations': 0, 'child_exit_code': None, 'child_bytes': 0, 'child_sha256': None,
               'child_emission': 'none', 'receipt_emission': 'prepared',
               'ordered_outcomes': 0, 'ordered_ids_sha256': None, 'late_stages': [],
               'finalizers': {}, 'termination': None,
               'origin': 'time.monotonic() at module import, after interpreter bootstrap',
               'runtime_or_targets_accessed': False,
               'claims': {'mock_pass_declared_here': False, 'operational_qualification': False,
                          'process_tree_terminated': None, 'receipt_capture_attested_here': False}}
    try:
        deadlines.check('preflight.start', deadlines.body)
        require(len(argv) == 1 and type(argv[0]) is str, 'exactly one argument: the pinned scope path')
        receipt['sink'] = sink_check()
        deadlines.check('scope.before', deadlines.body)
        # The scope file is the operator's independently pinned selection; its pin arrives through the
        # outer operator packet. Here it is read ONCE and the consumed bytes are recorded by digest.
        scope_raw = read_once(argv[0], open_pinned, deadlines.gate('scope.io', deadlines.body))
        receipt['scope_consumed'] = {'path': argv[0], 'bytes': len(scope_raw), 'sha256': digest(scope_raw)}
        scope = load_scope(scope_raw)
        deadlines.check('scope.after', deadlines.body)
        receipt['inputs_before'] = verify_rows(scope['inputs'], deadlines, 'inputs_before', deadlines.body, open_pinned)
        receipt['interpreter'] = verify_rows([scope['interpreter_pin']], deadlines, 'interpreter', deadlines.body, open_pinned)[0]
        receipt['timeout_binary'] = verify_rows([scope['timeout_pin']], deadlines, 'timeout', deadlines.body, open_pinned)[0]
        receipt['preserved_before'] = verify_rows(scope['preserved'], deadlines, 'preserved_before', deadlines.body, open_pinned)
        deadlines.check('roster.before', deadlines.body)
        roster_raw = open_pinned(scope['roster_pin'], gate=deadlines.gate('roster.io', deadlines.body))
        roster = Roster(json.loads(roster_raw.decode('utf-8', errors='strict')))   # the SAME bytes
        deadlines.check('roster.after', deadlines.body)
        receipt['roster'] = {'pin': dict(scope['roster_pin']), 'consumed_sha256': digest(roster_raw),
                             'count': roster.count, 'ids_sha256': digest(encode(list(roster.ids), SUPERVISOR_CAP))}
        require(not exists(scope['once_namespace_marker']), 'once namespace already used')
        deadlines.check('frame.before', deadlines.body)
        _frame(budget, 'preflight', {'scope': receipt['scope_consumed']['sha256'],
                                     'roster': receipt['roster']['consumed_sha256']},
               deadlines.gate('frame.write', deadlines.body))
        deadlines.check('launch.before', deadlines.body)
        child = popen(scope['argv'], cwd=scope['cwd'], stdin=subprocess.DEVNULL,
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                      env={'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'})
        # Child stays in the inherited process group so the outer `timeout` (default mode) covers it.
        receipt['child_invocations'] = 1
        data = collect(child, deadlines, finalizers)
        deadlines.check('wait.before', deadlines.body)
        receipt['child_exit_code'] = child.wait(timeout=deadlines.timeout(deadlines.body, 1.0))
        deadlines.check('wait.after', deadlines.body)
        receipt['child_bytes'] = len(data)
        receipt['child_sha256'] = digest(data)
        deadlines.check('forward.before', deadlines.body)
        emission['child'] = 'attempted'                              # latched BEFORE the write
        receipt['child_emission'] = 'attempted'
        budget.emit_child(data, deadlines.gate('forward.write', deadlines.body))
        emission['child'] = 'completed'
        receipt['child_emission'] = 'completed'
        deadlines.check('forward.after', deadlines.body)
        receipt['inputs_after'] = verify_rows(scope['inputs'], deadlines, 'inputs_after', deadlines.body, open_pinned)
        receipt['preserved_after'] = verify_rows(scope['preserved'], deadlines, 'preserved_after', deadlines.body, open_pinned)
        require(receipt['child_exit_code'] == 0, 'child exit must be 0')
        deadlines.check('parse.before', deadlines.body)
        outcomes = parse_terminal(data, roster)
        receipt['ordered_outcomes'] = len(outcomes)
        receipt['ordered_ids_sha256'] = digest(encode(list(outcomes), SUPERVISOR_CAP))
        deadlines.check('parse.after', deadlines.body)
    except Refused as error:
        data = getattr(error, 'partial_child_output', data)    # set only by collect_child_output
        if emission['child'] == 'attempted':
            emission['child'] = 'uncertain'
            receipt['child_emission'] = 'uncertain'
        _record_error(receipt, 'body', error, STATUS_REFUSED)
    except BaseException as error:  # noqa: BLE001 - bounded text into the same sink; never a bare traceback
        data = getattr(error, 'partial_child_output', data)
        if emission['child'] == 'attempted':
            emission['child'] = 'uncertain'
            receipt['child_emission'] = 'uncertain'
        _record_error(receipt, 'body', error, STATUS_UNKNOWN)
    finally:
        _cleanup(receipt, emission, child, data, budget, deadlines, finalizers)
    return _emit_receipt(receipt, emission, budget, deadlines, now)


def _read_once(path, open_pinned=None, gate=_no_gate, ops=os):
    """Read the scope file once with opened-descriptor checks; gated before/after each I/O action."""
    require(type(path) is str and os.path.isabs(path) and os.path.realpath(path) == path, 'scope path absolute realpath')
    s = os.lstat(path)
    require(stat.S_ISREG(s.st_mode), 'scope path is not a regular file')
    gate()
    fd = ops.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))

    def body(fd):
        gate()                                                         # post-open check, inside the cleanup boundary
        fs = ops.fstat(fd)
        gate()                                                         # adjacent check after stat
        require(stat.S_ISREG(fs.st_mode) and (fs.st_dev, fs.st_ino) == (s.st_dev, s.st_ino),
                'scope descriptor differs from the selected path')
        require(0 < fs.st_size <= SUPERVISOR_CAP, 'scope size bound')
        raw = _read_descriptor(fd, fs.st_size, ops, gate)
        require(len(raw) == fs.st_size, 'scope read length differs from descriptor size')
        return raw
    return _with_descriptor(fd, body, ops, gate)


def _cleanup(receipt, emission, child, data, budget, deadlines, finalizers):
    """Deadline-gated, once-only cleanup; failures are recorded, never raised; nothing is retried."""
    try:
        if child is not None:
            try:
                alive = child.poll() is None
            except BaseException as error:  # noqa: BLE001
                _record_error(receipt, 'poll', error, STATUS_UNKNOWN)
                alive = None
            if alive:
                if deadlines.before(deadlines.final):
                    try:
                        child.kill()                                   # at most one termination attempt
                    except BaseException as error:  # noqa: BLE001
                        _record_error(receipt, 'kill', error, STATUS_UNKNOWN)
                        receipt['termination'] = 'UNKNOWN: kill failed'
                    else:
                        if deadlines.before(deadlines.final):          # re-check AFTER kill, BEFORE wait
                            try:
                                child.wait(timeout=deadlines.timeout(deadlines.final, FINAL_SECONDS))
                                if deadlines.before(deadlines.final):  # re-check AFTER the reap
                                    receipt['termination'] = 'killed_and_reaped; tree not asserted'
                                else:
                                    receipt['termination'] = 'UNKNOWN: reap returned after the final cutoff'
                                    receipt['status'] = STATUS_UNKNOWN
                                    deadlines.late.append({'stage': 'wait.after', 'late_by_seconds': round(-deadlines.remaining(deadlines.final), 6)})
                            except BaseException as error:  # noqa: BLE001
                                _record_error(receipt, 'wait', error, STATUS_UNKNOWN)
                                receipt['termination'] = 'UNKNOWN: reap incomplete'
                        else:
                            receipt['termination'] = 'UNKNOWN: kill consumed the final window; no wait issued'
                            receipt['status'] = STATUS_UNKNOWN
                            deadlines.late.append({'stage': 'wait.skipped', 'late_by_seconds': round(-deadlines.remaining(deadlines.final), 6)})
                else:
                    receipt['termination'] = 'UNKNOWN: live child at final cutoff; no late termination issued'
                    receipt['status'] = STATUS_UNKNOWN
                    deadlines.late.append({'stage': 'termination.skipped', 'late_by_seconds': round(-deadlines.remaining(deadlines.final), 6)})
            elif alive is None:
                receipt['termination'] = 'UNKNOWN: poll failed'
            try:
                receipt['child_exit_code'] = child.poll()
            except BaseException as error:  # noqa: BLE001
                _record_error(receipt, 'poll', error, STATUS_UNKNOWN)
        if emission['child'] == 'none' and data and deadlines.before(deadlines.final):
            emission['child'] = 'attempted'                            # evidence retention, once, latched first
            receipt['child_emission'] = 'attempted'
            try:
                budget.emit_child(data, deadlines.gate('forwarding.write', deadlines.final))
                emission['child'] = 'completed'
                receipt['child_emission'] = 'completed'
                receipt['child_bytes'] = len(data)
                receipt['child_sha256'] = digest(data)
                if not deadlines.before(deadlines.final):              # re-check AFTER the emission
                    receipt['status'] = STATUS_UNKNOWN
                    deadlines.late.append({'stage': 'forwarding.after', 'late_by_seconds': round(-deadlines.remaining(deadlines.final), 6)})
            except BaseException as error:  # noqa: BLE001
                emission['child'] = 'uncertain'
                receipt['child_emission'] = 'uncertain'
                _record_error(receipt, 'forwarding', error, STATUS_UNKNOWN)
    except BaseException as error:  # noqa: BLE001
        _record_error(receipt, 'clock', error, STATUS_UNKNOWN)
    finally:
        receipt['finalizers'] = finalizers.finalize_all(lambda: deadlines.before(deadlines.final),
                                                        lambda: deadlines.before(deadlines.final))
        try:
            outcomes = receipt['finalizers'].values()
            if any(v.startswith('failed') for v in outcomes):
                _record_error(receipt, 'finalizers', Refused('finalizer failure'), STATUS_REFUSED)
            if any(v == 'unattempted_due_to_deadline' for v in outcomes):
                _record_error(receipt, 'finalizers', Refused('finalizer unattempted at final cutoff'), STATUS_UNKNOWN)
            if any(v == 'closed_late' for v in outcomes):
                _record_error(receipt, 'finalizers', Refused('a close returned after the final cutoff'), STATUS_UNKNOWN)
            if emission['child'] == 'uncertain':
                receipt['status'] = STATUS_UNKNOWN
        except BaseException as error:  # noqa: BLE001
            _record_error(receipt, 'clock', error, STATUS_UNKNOWN)


def _emit_receipt(receipt, emission, budget, deadlines, now):
    """At most one receipt emission attempt; the serialized intent is 'prepared' (or 'short'), never a
    self-attestation of completion. A fresh check runs after construction and before the first writer
    call; each suffix write is gated by the orchestration cutoff; nothing is started late."""
    try:
        receipt['late_stages'] = deadlines.late
        try:
            deadlines.check('receipt.before', deadlines.orch)
        except Refused as error:
            _record_error(receipt, 'receipt', error, STATUS_UNKNOWN)
            return 84                                                   # no late receipt write is started
        except BaseException as error:  # noqa: BLE001 - clock failure before any write: nothing attempted
            _record_error(receipt, 'clock', error, STATUS_UNKNOWN)
            return 84
        try:
            receipt['elapsed_seconds'] = round(now() - ORIGIN, 6)
            receipt['budget'] = {'child_bytes': budget.child_bytes,
                                 'supervisor_bytes_before_receipt': budget.supervisor_bytes}
            receipt['receipt_emission'] = 'prepared'                    # truthful pre-write intent
            raw = encode(receipt, SUPERVISOR_CAP) + b'\n'
        except BaseException as error:  # noqa: BLE001 - construction failed; nothing attempted yet
            _record_error(receipt, 'receipt', error, STATUS_UNKNOWN)
            raw = None
        if raw is None or not budget.fits_supervisor(len(raw)):
            if raw is not None:
                _record_error(receipt, 'receipt', Refused('receipt would exceed the output budget'), STATUS_UNKNOWN)
            short = encode({'schema': RECEIPT_SCHEMA, 'status': STATUS_UNKNOWN, 'error': receipt['error'],
                            'receipt_emission': 'short'}, SUPERVISOR_CAP) + b'\n'
            if not budget.fits_supervisor(len(short)):
                return 84
            raw = short
            receipt['status'] = STATUS_UNKNOWN
        try:
            deadlines.check('receipt.write.before', deadlines.orch)     # fresh check AFTER construction
        except Refused as error:
            _record_error(receipt, 'receipt', error, STATUS_UNKNOWN)
            return 84                                                   # construction consumed the window: no write
        except BaseException:  # noqa: BLE001
            return 84
        emission['receipt'] = 'attempted'                               # latched BEFORE the first writer call
        try:
            budget.emit_supervisor(raw, deadlines.gate('receipt.write', deadlines.orch))
        except BaseException:  # noqa: BLE001 - uncertain emission (incl. a late suffix): nothing more is written
            emission['receipt'] = 'uncertain'
            return 84
        emission['receipt'] = 'completed'                               # internal only; the bytes say 'prepared'
        try:
            late = not deadlines.before(deadlines.orch)
        except BaseException:  # noqa: BLE001
            return 84
        if late:
            return 84                                                   # completed late: non-PASS
        return 0 if receipt['status'] == STATUS_COMPLETE else 84
    except BaseException:  # noqa: BLE001 - construction/fallback failure before any write
        return 84


if __name__ == '__main__':
    raise SystemExit(main())
