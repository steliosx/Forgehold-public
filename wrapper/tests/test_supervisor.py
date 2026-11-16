"""Definitions for supervisor successor 03; no child process is used, and no real file or descriptor except in
ReadOnceTests and ClaimOnceTests (temporary directories, to exercise _read_once's and _claim_once's own checks).

Everything main() touches outside pure computation is injected through its keyword-only seams: now,
writer, popen, collect, open_pinned, read_once, sink_check, claim_once; open_pinned/_read_once take `ops` and
`gate`. The fakes model an exited or live child, a writer that acknowledges partially or raises, a clock that
moves by script or by fake hooks, pinned files that change between reads, and descriptor operations that
fail in chosen combinations. Rows that need a real child (ignored kill, stalled reap, escaped descendant,
outer kill, receipt/outer-exit disagreement) remain future scratch-scope fault injections.
"""
import json
import os
import stat
import unittest
from pathlib import Path

from wrapper import supervisor as sv
from wrapper.supervisor import Refused

ROOT = Path(__file__).resolve().parents[1]
ROSTER_PATH = ROOT / 'scope' / 'R60-EXPECTED-CLASS-METHOD-ROSTER-SPEC-DATA-20261010.json'
HEX0 = '0' * 64


def roster_spec():
    return json.loads(ROSTER_PATH.read_bytes())


def terminal_for(ids, count=None, ran_line=None, footer='OK'):
    lines = ['%s (%s) ... ok' % (full.split('.')[-1], full) for full in ids]
    count = len(ids) if count is None else count
    ran = ran_line if ran_line is not None else 'Ran %d tests in 0.460s' % count
    return ('\n'.join(lines) + '\n\n' + sv.SEPARATOR + '\n' + ran + '\n\n' + footer + '\n').encode()


# ----------------------------------------------------------------------------- pure parts

class RosterTests(unittest.TestCase):
    def test_pinned_roster_loads_27_ordered_ids(self):
        roster = sv.Roster(roster_spec())
        self.assertEqual((roster.count, len(roster.ids), roster.module), (27, 27, 'tests.test_quality_job'))
        self.assertEqual(roster.ids[0].split('.')[-2], 'B1JobModelTests')
        self.assertEqual(roster.ids[13].split('.')[-2], 'B1QualityModelTests')

    def test_roster_faults_refuse(self):
        base = roster_spec()
        def variant(mutate):
            spec = json.loads(json.dumps(base)); mutate(spec); return spec
        cases = [lambda s: s['expected_full_ids'].pop(), lambda s: s['expected_full_ids'].append(s['expected_full_ids'][0]),
                 lambda s: s['expected_full_ids'].reverse(), lambda s: s.__setitem__('top_level_count', 26),
                 lambda s: s['class_counts'].__setitem__('B1JobModelTests', 12),
                 lambda s: s['expected_full_ids'].__setitem__(0, 'other.module.B1JobModelTests.test_a'),
                 lambda s: s['expected_full_ids'].__setitem__(0, s['module'] + '.OnlyClass'),
                 lambda s: s['expected_full_ids'].__setitem__(0, s['module'] + '.B1JobModelTests.helper'),
                 lambda s: s.__setitem__('top_level_count', True),
                 lambda s: s.__setitem__('expected_full_ids', tuple(s['expected_full_ids'])),
                 lambda s: s.__setitem__('expected_full_ids', s['expected_full_ids'][13:] + s['expected_full_ids'][:13])]
        for index, mutate in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(Refused):
                    sv.Roster(variant(mutate))


class TerminalGrammarTests(unittest.TestCase):
    def setUp(self):
        self.roster = sv.Roster(roster_spec())
        self.ids = list(self.roster.ids)

    def test_exact_ordered_terminal_parses_to_the_roster(self):
        self.assertEqual(sv.parse_terminal(terminal_for(self.ids), self.roster), self.roster.ids)

    def test_reordered_duplicate_missing_extra_and_wrong_class_refuse(self):
        swapped = list(self.ids); swapped[0], swapped[1] = swapped[1], swapped[0]
        wrong_class = list(self.ids); wrong_class[0] = wrong_class[0].replace('B1JobModelTests', 'B1QualityModelTests')
        for ids in (swapped, self.ids[:26], self.ids + [self.ids[0]], self.ids[:26] + [self.ids[0]], wrong_class, list(reversed(self.ids))):
            with self.subTest(n=len(ids)):
                with self.assertRaises(Refused):
                    sv.parse_terminal(terminal_for(ids), self.roster)

    def test_name_full_id_mismatch_refuses(self):
        raw = terminal_for(self.ids); first = self.ids[0]; name = first.split('.')[-1]
        bad = raw.replace(('%s (%s)' % (name, first)).encode(), ('test_other (%s)' % first).encode(), 1)
        with self.assertRaises(Refused):
            sv.parse_terminal(bad, self.roster)

    def test_non_ok_statuses_and_stray_lines_refuse(self):
        raw = terminal_for(self.ids)
        for new in (b' ... FAIL\n', b' ... ERROR\n', b" ... skipped 'x'\n", b' ... ok\nstray line\n'):
            with self.subTest(new=new):
                with self.assertRaises(Refused):
                    sv.parse_terminal(raw.replace(b' ... ok\n', new, 1), self.roster)

    def test_summary_conflicts_and_footer_faults_refuse(self):
        for raw in (terminal_for(self.ids, ran_line='Ran 26 tests in 0.1s'), terminal_for(self.ids, ran_line='Ran 27 tests in 0.1s\nRan 27 tests in 0.1s'),
                    terminal_for(self.ids, ran_line='Ran 27 tests in xs'), terminal_for(self.ids, footer='FAILED (failures=1)'),
                    terminal_for(self.ids, footer='OK (skipped=1)'), terminal_for(self.ids)[:-1], terminal_for(self.ids) + b'\n',
                    terminal_for(self.ids) + b'OK\n', b'', b'\xff\xfe' + terminal_for(self.ids)):
            with self.subTest(tail=raw[-40:]):
                with self.assertRaises(Refused):
                    sv.parse_terminal(raw, self.roster)

    def test_summary_count_mismatch_with_valid_seconds_refuses_on_count(self):
        with self.assertRaises(Refused) as caught:
            sv.parse_terminal(terminal_for(self.ids, ran_line='Ran 26 tests in 0.460s'), self.roster)
        self.assertEqual(str(caught.exception), 'summary count differs from roster')

    def test_missing_or_misplaced_separator_and_extra_blank_lines_refuse(self):
        raw = terminal_for(self.ids); sep = (sv.SEPARATOR + '\n').encode()
        first_line_end = raw.index(b'\n') + 1
        for variant in (raw.replace(sep, b'', 1), raw.replace(sep, sep + sep, 1), sep + raw,
                        raw[:first_line_end] + b'\n' + raw[first_line_end:],
                        raw.replace(b'\n\n' + sep, b'\n' + sep, 1), raw.replace(b's\n\nOK\n', b's\nOK\n', 1)):
            with self.subTest(head=variant[:30]):
                with self.assertRaises(Refused):
                    sv.parse_terminal(variant, self.roster)

    def test_non_ascii_digits_and_loose_seconds_refuse(self):
        for ran in ('Ran ٢٧ tests in 0.460s', 'Ran ²7 tests in 0.460s', 'Ran 27 tests in .5s',
                    'Ran 27 tests in 5.s', 'Ran 27 tests in 0.46s', 'Ran 27 tests in 0.4600s', 'Ran 27 tests in 0.460 s'):
            with self.subTest(ran=ran):
                with self.assertRaises(Refused):
                    sv.parse_terminal(terminal_for(self.ids, ran_line=ran), self.roster)

    def test_child_output_over_cap_refuses_before_decode(self):
        with self.assertRaises(Refused):
            sv.parse_terminal(terminal_for(self.ids) + b' ' * sv.CHILD_CAP, self.roster)


class Sink:
    """Scripted writer: `acks` is a list of per-call acknowledgements; an exception instance is raised.
    `on_call` (optional) runs before each acknowledgement, so a definition can move a fake clock."""
    def __init__(self, acks=None, on_call=None):
        self.data = bytearray(); self.acks = list(acks or []); self.calls = 0; self.on_call = on_call
        self.args = []                                    # every raw writer argument, recorded before its ack
    def __call__(self, raw):
        self.calls += 1
        self.args.append(bytes(raw))
        if self.on_call:
            self.on_call(self.calls)
        if self.acks:
            ack = self.acks.pop(0)
            if isinstance(ack, BaseException):
                raise ack
            if type(ack) is int and 0 < ack <= len(raw):
                self.data.extend(raw[:ack])
            return ack
        self.data.extend(raw); return len(raw)


class Clock:
    """Scripted clock: readings consumed in order, the last repeats; set(t) moves it; fail_at_call raises."""
    def __init__(self, *readings, fail_at_call=None):
        self.readings = list(readings); self.calls = 0; self.fail_at_call = fail_at_call
    def set(self, t):
        self.readings = [t]
    def __call__(self):
        self.calls += 1
        if self.fail_at_call is not None and self.calls == self.fail_at_call:
            raise ValueError('clock failed on call %d' % self.calls)
        reading = self.readings.pop(0) if len(self.readings) > 1 else self.readings[0]
        if isinstance(reading, BaseException):
            raise reading
        return reading


class BudgetTests(unittest.TestCase):
    def test_caps_and_aggregate_exactly_at_limit_pass(self):
        sink = Sink(); budget = sv.Budget(sink)
        budget.emit_child(b'c' * sv.CHILD_CAP); budget.emit_supervisor(b's' * (sv.SUPERVISOR_CAP - 1)); budget.emit_supervisor(b's')
        self.assertEqual((budget.total, len(sink.data)), (sv.AGGREGATE_CAP, sv.AGGREGATE_CAP))
        self.assertFalse(budget.fits_supervisor(1)); self.assertTrue(budget.fits_supervisor(0))

    def test_one_byte_over_any_cap_refuses_without_writing(self):
        sink = Sink(); budget = sv.Budget(sink)
        with self.assertRaises(Refused):
            budget.emit_child(b'c' * (sv.CHILD_CAP + 1))
        self.assertEqual(len(sink.data), 0)
        budget.emit_child(b'c' * sv.CHILD_CAP)
        with self.assertRaises(Refused):
            budget.emit_child(b'c')
        with self.assertRaises(Refused):
            budget.emit_supervisor(b's' * (sv.SUPERVISOR_CAP + 1))
        self.assertEqual(len(sink.data), sv.CHILD_CAP)

    def test_acknowledged_partial_write_continues_with_the_suffix_only(self):
        sink = Sink(acks=[3, 4]); budget = sv.Budget(sink)
        budget.emit_supervisor(b'0123456789')
        self.assertEqual(bytes(sink.data), b'0123456789')
        self.assertEqual((sink.calls, budget.supervisor_bytes), (3, 10))

    def test_zero_bool_float_or_over_reported_acknowledgements_are_uncertain_and_stay_charged(self):
        for ack in (0, True, 10.0, 11, -1, None, '10'):
            with self.subTest(ack=ack):
                sink = Sink(acks=[ack]); budget = sv.Budget(sink)
                with self.assertRaises(Refused):
                    budget.emit_supervisor(b'0123456789')
                self.assertEqual((budget.supervisor_bytes, sink.calls), (10, 1))

    def test_reservation_is_counted_before_the_write_and_never_released(self):
        sink = Sink(acks=[3, OSError('sink gone')]); budget = sv.Budget(sink)
        with self.assertRaises(OSError):
            budget.emit_supervisor(b'0123456789')
        self.assertEqual(budget.supervisor_bytes, 10)
        self.assertFalse(budget.fits_supervisor(sv.SUPERVISOR_CAP - 9)); self.assertTrue(budget.fits_supervisor(sv.SUPERVISOR_CAP - 10))

    def test_first_short_acknowledgement_crossing_the_cutoff_issues_no_suffix_write(self):
        clock = Clock(100.0); d = sv.Deadlines(100.0, clock)
        sink = Sink(acks=[3], on_call=lambda n: clock.set(128.0) if n == 1 else None)   # the first write consumes the window
        budget = sv.Budget(sink)
        with self.assertRaises(Refused):
            budget.emit_supervisor(b'0123456789', d.gate('receipt.write', d.orch))
        self.assertEqual(sink.calls, 1)                                 # no suffix call after expiry
        self.assertEqual(budget.supervisor_bytes, 10)                   # the whole attempt stays charged
        self.assertEqual(d.late[0]['stage'], 'receipt.write')

    def test_gate_refusing_before_the_first_write_means_zero_writer_calls(self):
        clock = Clock(128.0); d = sv.Deadlines(100.0, clock); sink = Sink(); budget = sv.Budget(sink)
        with self.assertRaises(Refused):
            budget.emit_supervisor(b'x', d.gate('receipt.write', d.orch))
        self.assertEqual((sink.calls, budget.supervisor_bytes), (0, 1))

    def test_non_bytes_refuses(self):
        with self.assertRaises(Refused):
            sv.Budget(Sink()).emit_child('text')


class DeadlineTests(unittest.TestCase):
    def test_cutoffs_are_absolute_from_one_origin(self):
        d = sv.Deadlines(100.0, Clock(100.0))
        self.assertEqual((d.body, d.final, d.orch), (124.0, 127.0, 128.0))
        self.assertEqual(d.check('preflight.start', d.body), 100.0); self.assertEqual(d.late, [])

    def test_equality_with_cutoff_is_late_and_recorded(self):
        d = sv.Deadlines(100.0, Clock(124.0, 128.5))
        with self.assertRaises(Refused):
            d.check('read.after', d.body)
        self.assertEqual(d.late, [{'stage': 'read.after', 'late_by_seconds': 0.0}])
        with self.assertRaises(Refused):
            d.check('receipt.before', d.orch)
        self.assertEqual(len(d.late), 2)

    def test_remaining_has_no_floor_and_timeout_refuses_when_nothing_remains(self):
        d = sv.Deadlines(100.0, Clock(100.0, 123.95, 124.0, 129.0))
        self.assertEqual(d.timeout(d.body, 0.1), 0.1)
        self.assertAlmostEqual(d.timeout(d.body, 0.1), 0.05)
        with self.assertRaises(Refused):
            d.timeout(d.body, 0.1)
        self.assertEqual(d.remaining(d.body), -5.0)

    def test_gate_is_a_named_check(self):
        d = sv.Deadlines(100.0, Clock(127.0)); gate = d.gate('x.io', d.final)
        with self.assertRaises(Refused):
            gate()
        self.assertEqual(d.late[0]['stage'], 'x.io')


class Handle:
    def __init__(self, fail=None, on_close=None):
        self.closes = 0; self.fail = fail; self.on_close = on_close
    def close(self):
        self.closes += 1
        if self.on_close:
            self.on_close()
        if self.fail:
            raise self.fail


class FinalizerTests(unittest.TestCase):
    def test_each_handle_closed_once_and_recorded(self):
        f = sv.Finalizers(); a, b = Handle(), Handle(); f.acquire('a', a); f.acquire('b', b)
        self.assertEqual(f.finalize('a'), 'closed'); self.assertEqual(f.finalize('a'), 'closed')
        self.assertEqual(f.finalize_all(), {'a': 'closed', 'b': 'closed'}); self.assertEqual((a.closes, b.closes), (1, 1))

    def test_eof_close_is_a_recorded_attempt_and_prevents_double_close(self):
        f = sv.Finalizers(); h = Handle(); f.acquire('child_stdout', h)
        f.finalize('child_stdout'); f.finalize_all()
        self.assertEqual((h.closes, f.outcomes['child_stdout']), (1, 'closed'))

    def test_one_failure_does_not_suppress_others_and_is_never_retried(self):
        f = sv.Finalizers(); bad, good = Handle(OSError('EBADF')), Handle(); f.acquire('selector', bad); f.acquire('capture', good)
        self.assertEqual(f.finalize_all(), {'selector': 'failed:OSError', 'capture': 'closed'})
        f.finalize_all(); self.assertEqual((bad.closes, good.closes), (1, 1))

    def test_several_failures_all_attempted_once(self):
        f = sv.Finalizers(); handles = [Handle(ValueError('x')), Handle(OSError('y')), Handle(RuntimeError('z'))]
        for index, h in enumerate(handles):
            f.acquire('h%d' % index, h)
        self.assertEqual(sorted(f.finalize_all().values()), ['failed:OSError', 'failed:RuntimeError', 'failed:ValueError'])
        self.assertEqual([h.closes for h in handles], [1, 1, 1])

    def test_partial_acquisition_closes_only_acquired_handles(self):
        f = sv.Finalizers(); f.acquire('a', Handle())
        self.assertEqual(f.finalize('never_acquired'), 'not_acquired')
        self.assertEqual(f.finalize_all(), {'a': 'closed', 'never_acquired': 'not_acquired'})
        with self.assertRaises(Refused):
            f.acquire('a', Handle())

    def test_attempt_is_marked_before_close_even_if_close_raises_base_exception(self):
        f = sv.Finalizers(); h = Handle(KeyboardInterrupt()); f.acquire('k', h)
        self.assertEqual((f.finalize('k'), h.closes), ('failed:KeyboardInterrupt', 1))

    def test_first_close_consuming_the_window_leaves_later_handles_unattempted(self):
        state = {'t': 126.9}
        f = sv.Finalizers(); first, second = Handle(on_close=lambda: state.__setitem__('t', 127.5)), Handle()
        f.acquire('first', first); f.acquire('second', second)
        outcomes = f.finalize_all(lambda: state['t'] < 127.0, lambda: state['t'] < 127.0)
        self.assertEqual(outcomes, {'first': 'closed_late', 'second': 'unattempted_due_to_deadline'})
        self.assertEqual((first.closes, second.closes), (1, 0))
        self.assertEqual(f.finalize_all(lambda: True, lambda: True), outcomes)   # never retried

    def test_last_or_only_close_returning_after_the_cutoff_is_closed_late(self):
        state = {'t': 126.9}
        f = sv.Finalizers(); only = Handle(on_close=lambda: state.__setitem__('t', 127.5)); f.acquire('only', only)
        self.assertEqual(f.finalize_all(lambda: state['t'] < 127.0, lambda: state['t'] < 127.0), {'only': 'closed_late'})
        self.assertEqual(only.closes, 1)                               # the one close did happen; recorded, not retried

    def test_close_returning_exactly_at_the_cutoff_is_late_and_in_time_is_closed(self):
        for t_after, expected in ((127.0, 'closed_late'), (126.99, 'closed')):
            with self.subTest(t_after=t_after):
                state = {'t': 126.9}
                f = sv.Finalizers(); h = Handle(on_close=lambda: state.__setitem__('t', t_after)); f.acquire('h', h)
                self.assertEqual(f.finalize_all(lambda: state['t'] < 127.0, lambda: state['t'] < 127.0), {'h': expected})

    def test_failing_predicates_count_as_not_allowed_or_not_timely(self):
        def broken():
            raise StopIteration
        f = sv.Finalizers(); h = Handle(); f.acquire('h', h)
        self.assertEqual(f.finalize_all(broken), {'h': 'unattempted_due_to_deadline'}); self.assertEqual(h.closes, 0)
        g = sv.Finalizers(); k = Handle(); g.acquire('k', k)
        self.assertEqual(g.finalize_all(lambda: True, broken), {'k': 'closed_late'}); self.assertEqual(k.closes, 1)


class FakeStat:
    def __init__(self, mode=stat.S_IFREG | 0o600, dev=1, ino=7, size=0):
        self.st_mode, self.st_dev, self.st_ino, self.st_size = mode, dev, ino, size


class SinkVerificationTests(unittest.TestCase):
    def test_same_fresh_append_only_regular_file_on_both_fds_passes(self):
        stats = {1: FakeStat(), 2: FakeStat()}
        self.assertEqual(sv.verify_sink(fstat=lambda fd: stats[fd], getfl=lambda fd: os.O_WRONLY | os.O_APPEND), {'dev': 1, 'ino': 7})

    def test_pipe_different_file_nonempty_or_non_append_refuse(self):
        regular = FakeStat()
        for stats, flags in (({1: FakeStat(mode=stat.S_IFIFO | 0o600), 2: regular}, os.O_WRONLY | os.O_APPEND),
                             ({1: regular, 2: FakeStat(ino=8)}, os.O_WRONLY | os.O_APPEND),
                             ({1: FakeStat(size=1), 2: FakeStat(size=1)}, os.O_WRONLY | os.O_APPEND),
                             ({1: regular, 2: regular}, os.O_WRONLY), ({1: regular, 2: regular}, os.O_RDONLY | os.O_APPEND)):
            with self.subTest(flags=flags):
                with self.assertRaises(Refused):
                    sv.verify_sink(fstat=lambda fd, s=stats: s[fd], getfl=lambda fd, f=flags: f)


def pin_row(path='/x/y', nbytes=1, mode='0400', sha=HEX0):
    return {'path': path, 'bytes': nbytes, 'mode': mode, 'sha256': sha}


class PinRowTests(unittest.TestCase):
    def test_literal_types_required(self):
        sv.check_pin_row(pin_row()); sv.check_pin_row(pin_row(nbytes=0))
        for row in (pin_row(nbytes=1.0), pin_row(nbytes=True), pin_row(nbytes=-1), pin_row(nbytes='1'),
                    pin_row(mode=256), pin_row(mode='400'), pin_row(mode='0o400'), pin_row(path='x/y'),
                    pin_row(sha='G' * 64), dict(pin_row(), extra=1), {k: v for k, v in pin_row().items() if k != 'mode'}):
            with self.subTest(row=row):
                with self.assertRaises(Refused):
                    sv.check_pin_row(row)


class FakeOps:
    """os-like fake for open_pinned/_read_once: scripted fstat/read/close behaviour, one descriptor."""
    def __init__(self, content=b'data', mode=0o400, fstat_error=None, read_error=None, close_error=None, size=None):
        self.content = content; self.mode = mode; self.size = len(content) if size is None else size
        self.fstat_error = fstat_error; self.read_error = read_error; self.close_error = close_error
        self.opens = 0; self.closes = 0; self.reads = 0; self.offset = 0
    def open(self, path, flags):
        self.opens += 1; return 9
    def fstat(self, fd):
        if self.fstat_error:
            raise self.fstat_error
        return FakeStat(mode=stat.S_IFREG | self.mode, size=self.size)
    def read(self, fd, n):
        self.reads += 1
        if self.read_error:
            raise self.read_error
        chunk = self.content[self.offset:self.offset + n]; self.offset += len(chunk); return chunk
    def close(self, fd):
        self.closes += 1
        if self.close_error:
            raise self.close_error


class OpenPinnedTests(unittest.TestCase):
    """open_pinned with fake descriptor operations: primary/secondary preservation and single close."""

    def row(self, content=b'data', mode='0400'):
        return {'path': '/p/f', 'bytes': len(content), 'mode': mode, 'sha256': sv.digest(content)}

    def test_good_read_returns_exact_bytes_with_one_open_and_one_close(self):
        ops = FakeOps(b'data')
        self.assertEqual(sv.open_pinned(self.row(), ops=ops), b'data')
        self.assertEqual((ops.opens, ops.closes), (1, 1))
        self.assertGreaterEqual(ops.reads, 2)                           # bytes+1 read until EOF

    def test_fstat_primary_plus_close_secondary(self):
        e1, e2 = OSError('fstat E1'), OSError('close E2')
        ops = FakeOps(fstat_error=e1, close_error=e2)
        with self.assertRaises(OSError) as caught:
            sv.open_pinned(self.row(), ops=ops)
        self.assertIs(caught.exception, e1)                             # the first failure stays primary
        self.assertEqual(getattr(e1, '__secondary_close__', None), {'type': 'OSError', 'text': 'close E2'})
        self.assertEqual(ops.closes, 1)                                 # one close attempt, no retry

    def test_read_primary_plus_close_secondary(self):
        e1, e2 = OSError('read E1'), ValueError('close E2')
        ops = FakeOps(read_error=e1, close_error=e2)
        with self.assertRaises(OSError) as caught:
            sv.open_pinned(self.row(), ops=ops)
        self.assertIs(caught.exception, e1)
        self.assertEqual(getattr(e1, '__secondary_close__', None)['type'], 'ValueError')
        self.assertEqual(ops.closes, 1)

    def test_primary_only_has_no_secondary_and_close_only_error_is_itself_primary(self):
        e1 = OSError('fstat E1'); ops = FakeOps(fstat_error=e1)
        with self.assertRaises(OSError) as caught:
            sv.open_pinned(self.row(), ops=ops)
        self.assertIs(caught.exception, e1); self.assertFalse(hasattr(e1, '__secondary_close__'))
        e2 = OSError('close only'); ops = FakeOps(b'data', close_error=e2)
        with self.assertRaises(OSError) as caught:
            sv.open_pinned(self.row(), ops=ops)
        self.assertIs(caught.exception, e2); self.assertEqual(ops.closes, 1)

    def test_validation_refusals_are_primary_and_close_still_happens_once(self):
        for ops, row in ((FakeOps(b'data', mode=0o644), self.row()),                      # mode differs
                         (FakeOps(b'data', size=5), self.row()),                           # size differs
                         (FakeOps(b'datx'), self.row()),                                   # digest differs
                         (FakeOps(b'data' + b'!', size=4), self.row())):                   # excess bytes
            with self.subTest():
                with self.assertRaises(Refused):
                    sv.open_pinned(row, ops=ops)
                self.assertEqual(ops.closes, 1)

    def test_gate_refusing_before_read_means_no_read_and_one_close(self):
        ops = FakeOps(b'data')
        calls = {'n': 0}
        def gate():
            calls['n'] += 1
            if calls['n'] == 2:                                          # the gate before the first read
                raise Refused('deadline reached: x.io')
        with self.assertRaises(Refused):
            sv.open_pinned(self.row(), ops=ops, gate=gate)
        self.assertEqual((ops.reads, ops.closes), (0, 1))

    def test_record_error_fills_bounded_close_slot_from_the_primary(self):
        receipt = {'status': sv.STATUS_COMPLETE, 'error': None, 'secondary': {}}
        e1 = OSError('fstat E1'); e1.__secondary_close__ = {'type': 'OSError', 'text': 'close E2'}
        sv._record_error(receipt, 'body', e1, sv.STATUS_UNKNOWN)
        self.assertEqual(receipt['error']['type'], 'OSError')
        self.assertEqual(receipt['secondary']['close'], {'type': 'OSError', 'text': 'close E2', 'stage': 'close'})
        self.assertEqual(receipt['status'], sv.STATUS_UNKNOWN)


class ClaimOnceTests(unittest.TestCase):
    """_claim_once creates the marker with O_EXCL; any existing entry, even a dangling symlink, refuses."""

    def test_first_claim_creates_the_marker_and_a_second_refuses(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, '.once')
            sv._claim_once(marker)
            self.assertTrue(stat.S_ISREG(os.lstat(marker).st_mode))
            with self.assertRaisesRegex(Refused, 'once namespace already used'):
                sv._claim_once(marker)

    def test_dangling_symlink_refuses_and_its_target_is_not_created(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            target, marker = os.path.join(d, 'target'), os.path.join(d, '.once')
            os.symlink(target, marker)
            with self.assertRaisesRegex(Refused, 'once namespace already used'):
                sv._claim_once(marker)
            self.assertFalse(os.path.lexists(target))

    def test_missing_folder_refuses_without_creating_it(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, 'absent', '.once')
            with self.assertRaisesRegex(Refused, 'once namespace marker not created: FileNotFoundError'):
                sv._claim_once(marker)
            self.assertFalse(os.path.lexists(os.path.dirname(marker)))


class ReadOnceTests(unittest.TestCase):
    """_read_once's path and identity checks, which every main() test fakes out."""

    def test_symlinked_scope_path_refuses(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(os.path.realpath(d), 'scope.json')
            with open(real, 'wb') as f:
                f.write(b'{}')
            link = os.path.join(os.path.realpath(d), 'link.json')
            os.symlink(real, link)
            with self.assertRaisesRegex(Refused, 'scope path absolute realpath'):
                sv._read_once(link)

    def test_descriptor_identity_differing_from_the_path_refuses(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(os.path.realpath(d), 'scope.json')
            with open(real, 'wb') as f:
                f.write(b'{}')
            ops = FakeOps(b'{}')
            ops.fstat = lambda fd: FakeStat(mode=stat.S_IFREG | 0o400, dev=-1, ino=-1, size=2)
            with self.assertRaisesRegex(Refused, 'scope descriptor differs from the selected path'):
                sv._read_once(real, ops=ops)
            self.assertEqual(ops.closes, 1)


class ScopeTests(unittest.TestCase):
    def scope(self):
        pin = pin_row()
        return {'argv': ['/usr/bin/python3.14', '-I', '-B', '-m', 'unittest', 'discover', '-s', '/r/tests', '-t', '/r', '-v'],
                'cwd': '/r', 'inputs': [pin], 'interpreter_pin': dict(pin, path='/usr/bin/python3.14'),
                'timeout_pin': dict(pin, path='/usr/bin/timeout'), 'roster_pin': dict(pin), 'preserved': [dict(pin)],
                'once_namespace_marker': '/r/.once', 'bounds': dict(sv.BOUNDS)}

    def encode(self, scope):
        return json.dumps(scope).encode()

    def test_scope_equal_to_constants_loads(self):
        self.assertEqual(sv.load_scope(self.encode(self.scope()))['cwd'], '/r')

    def test_duplicate_scope_key_refuses(self):

        raw = self.encode(self.scope())
        raw = raw[:-1] + b', "argv": ["/usr/bin/python3.14", "-I", "-t", "/r"]}'
        with self.assertRaisesRegex(Refused, 'duplicate scope JSON key'):
            sv.load_scope(raw)

    def test_any_bound_deviation_knob_or_type_trap_refuses(self):
        for key, value in (('child_cap_bytes', 49153), ('aggregate_cap_bytes', 65535), ('body_seconds', 25), ('whole_operation_seconds', 31),
                           ('invocations', 2), ('retry', True), ('invocations', True), ('retry', 0), ('body_seconds', 24.0), ('aggregate_cap_bytes', 65536.0)):
            with self.subTest(key=key, value=value):
                scope = self.scope(); scope['bounds'][key] = value
                with self.assertRaises(Refused):
                    sv.load_scope(self.encode(scope))
        scope = self.scope(); scope['bounds']['extra_budget'] = 1
        with self.assertRaises(Refused):
            sv.load_scope(self.encode(scope))

    def test_cwd_interpreter_and_pin_shape_faults_refuse(self):
        for mutate in (lambda s: s.__setitem__('cwd', '/other'), lambda s: s['argv'].__setitem__(0, '/usr/bin/python3'),
                       lambda s: s['preserved'].__setitem__(0, {'path': '/x'}), lambda s: s['roster_pin'].__setitem__('sha256', 'G' * 64),
                       lambda s: s.pop('once_namespace_marker'), lambda s: s['roster_pin'].__setitem__('bytes', 1.0),
                       lambda s: s['inputs'][0].__setitem__('bytes', True)):
            with self.subTest():
                scope = self.scope(); mutate(scope)
                with self.assertRaises(Refused):
                    sv.load_scope(self.encode(scope))


# ----------------------------------------------------------------------------- main() with fakes only

class FakeChild:
    """A child whose output was already collected; stdout is never a real descriptor."""
    def __init__(self, exit_code=0, alive=False, on_poll=None, on_kill=None):
        self.exit_code = exit_code; self.alive = alive; self.on_poll = on_poll; self.on_kill = on_kill
        self.kills = 0; self.waits = 0; self.polls = 0; self.stdout = None
    def poll(self):
        self.polls += 1
        if self.on_poll:
            self.on_poll()
        return None if self.alive else self.exit_code
    def wait(self, timeout=None):
        self.waits += 1
        if self.alive:
            raise sv.subprocess.TimeoutExpired('argv', timeout)
        return self.exit_code
    def kill(self):
        self.kills += 1
        if self.on_kill:
            self.on_kill()


class Files:
    """open_pinned fake: (bytes, mode) per path; `later` replaces the bytes after the first read of a path.
    Accepts and calls the gate like the real function (before 'open' and before/after the single read)."""
    def __init__(self, store, later=None):
        self.store = dict(store); self.later = dict(later or {}); self.reads = {}
    def __call__(self, row, ops=None, gate=sv._no_gate):
        sv.check_pin_row(row)
        gate()
        path = row['path']
        self.reads[path] = self.reads.get(path, 0) + 1
        raw, mode = self.store[path]
        if path in self.later and self.reads[path] > 1:
            raw = self.later[path]
        gate()
        if mode != row['mode'] or len(raw) != row['bytes'] or sv.digest(raw) != row['sha256']:
            raise Refused('selected input pin conflict: ' + path)
        return raw


def pinned(path, raw, mode='0400'):
    return {'path': path, 'bytes': len(raw), 'mode': mode, 'sha256': sv.digest(raw)}


def build_scope_and_files(roster_raw):
    interp, tmo, inp, pres = b'I', b'T', b'in', b'pres'
    scope = {'argv': ['/usr/bin/python3.14', '-I', '-B', '-m', 'unittest', 'discover', '-s', '/r/tests', '-t', '/r', '-v'],
             'cwd': '/r', 'inputs': [pinned('/r/in', inp)], 'interpreter_pin': pinned('/usr/bin/python3.14', interp, '0755'),
             'timeout_pin': pinned('/usr/bin/timeout', tmo, '0755'), 'roster_pin': pinned('/r/roster.json', roster_raw),
             'preserved': [pinned('/p/marker', pres)], 'once_namespace_marker': '/r/.once', 'bounds': dict(sv.BOUNDS)}
    scope_raw = json.dumps(scope).encode()
    files = Files({'/r/in': (inp, '0400'), '/usr/bin/python3.14': (interp, '0755'), '/usr/bin/timeout': (tmo, '0755'),
                   '/r/roster.json': (roster_raw, '0400'), '/p/marker': (pres, '0400'), '/r/scope.json': (scope_raw, '0400')})
    return scope_raw, files


def frame_length():
    return len(sv.encode({'frame': 'preflight', 'value': {'scope': HEX0, 'roster': HEX0}}, 16384)) + 1


def last_json_line(sink):
    return json.loads(bytes(sink.data).decode().strip().split('\n')[-1])


def json_suffix_at(sink, offset):
    """Parse the receipt that starts at a KNOWN byte boundary of a controlled fake sink: the suffix must be exactly
    one complete JSON object followed by its single terminal newline, with the receipt schema. For cases where a
    truncated child prefix precedes the receipt on the same line (no delimiter is injected anywhere)."""
    suffix = bytes(sink.data)[offset:]
    if not suffix.endswith(b'\n') or suffix.count(b'\n') != 1:
        raise AssertionError('receipt suffix is not exactly one newline-terminated line')
    receipt = json.loads(suffix[:-1].decode('utf-8'))
    if type(receipt) is not dict or receipt.get('schema') != sv.RECEIPT_SCHEMA:
        raise AssertionError('receipt suffix does not carry the receipt schema')
    return receipt


class MainPathModelTests(unittest.TestCase):
    """main() with every external touch point faked; no Popen, no descriptor, no file."""

    def setUp(self):
        self.roster_raw = ROSTER_PATH.read_bytes()
        self.ids = list(sv.Roster(json.loads(self.roster_raw)).ids)
        self.output = terminal_for(self.ids)
        self.scope_raw, self.files = build_scope_and_files(self.roster_raw)

    def run_main(self, sink, clock, child=None, output=None, files=None, claim_once=None,
                 read_once=None, collect=None):
        if claim_once is None:
            def claim_once(path, gate):       # models the real claim: one gate before and one after
                gate(); gate()
        child = FakeChild() if child is None else child
        output = self.output if output is None else output
        files = self.files if files is None else files
        if read_once is None:
            def read_once(path, op, gate, raw=self.scope_raw):
                return files({'path': path, 'bytes': len(raw), 'mode': '0400', 'sha256': sv.digest(raw)}, gate=gate)
        collect = (lambda c, d, f: output) if collect is None else collect
        return sv.main(['/r/scope.json'], now=clock, writer=sink, popen=lambda *a, **k: child, collect=collect,
                       open_pinned=files, read_once=read_once, sink_check=lambda: {'dev': 1, 'ino': 7}, claim_once=claim_once)

    def test_complete_path_emits_child_once_then_a_prepared_receipt_and_exits_0(self):
        sink = Sink(); child = FakeChild()
        code = self.run_main(sink, Clock(sv.ORIGIN), child)
        self.assertEqual(code, 0)
        receipt = last_json_line(sink)
        self.assertEqual(receipt['status'], sv.STATUS_COMPLETE)
        self.assertEqual(receipt['child_emission'], 'completed')      # the child write finished before serialization
        self.assertEqual(receipt['receipt_emission'], 'prepared')     # pre-write intent only; never 'completed'
        self.assertFalse(receipt['claims']['receipt_capture_attested_here'])
        self.assertEqual(receipt['ordered_outcomes'], 27)
        self.assertEqual(bytes(sink.data).count(self.output), 1)
        self.assertEqual(receipt['child_sha256'], sv.digest(self.output))
        self.assertEqual(receipt['roster']['consumed_sha256'], sv.digest(self.roster_raw))
        self.assertEqual(self.files.reads['/r/roster.json'], 1)
        self.assertEqual((child.kills, child.waits), (0, 1))
        self.assertEqual(receipt['finalizers'], {})
        self.assertNotIn(b'"receipt_emission":"completed"', bytes(sink.data))

    def test_child_forwarding_prefix_then_raise_is_one_attempt_never_retried(self):

        # prefix plus the receipt as one line. The receipt is read at its KNOWN boundary instead; no delimiter is
        # injected and the supervisor is unchanged.
        child = FakeChild()
        sink = Sink(acks=[frame_length(), 10, OSError('sink gone')])
        code = self.run_main(sink, Clock(sv.ORIGIN), child)
        self.assertEqual(code, 84)
        # exactly four writer calls: preflight, full child, child suffix (raises), receipt; no fifth, no restart
        self.assertEqual(sink.calls, 4)
        self.assertEqual(len(sink.args), 4)
        self.assertEqual(len(sink.args[0]), frame_length())
        self.assertEqual(sink.args[1], self.output)
        self.assertEqual(sink.args[2], self.output[10:])
        # captured bytes are exactly preflight + the acknowledged child prefix + the one receipt line
        self.assertEqual(bytes(sink.data), sink.args[0] + self.output[:10] + sink.args[3])
        receipt = json_suffix_at(sink, frame_length() + 10)
        self.assertEqual(bytes(sink.data)[frame_length() + 10:], sink.args[3])
        self.assertEqual((receipt['child_emission'], receipt['status']), ('uncertain', sv.STATUS_UNKNOWN))
        self.assertEqual(receipt['receipt_emission'], 'prepared')
        self.assertFalse(receipt['claims']['receipt_capture_attested_here'])
        self.assertEqual(receipt['child_invocations'], 1)
        self.assertEqual(receipt['budget']['child_bytes'], len(self.output))          # full child reservation
        self.assertEqual((receipt['child_bytes'], receipt['child_sha256']), (len(self.output), sv.digest(self.output)))
        self.assertEqual(receipt['error'], {'type': 'OSError', 'text': 'sink gone', 'stage': 'body'})
        self.assertEqual(bytes(sink.data).count(self.output), 0)                     # the full child never landed
        self.assertEqual(bytes(sink.data)[frame_length():frame_length() + 10], self.output[:10])

    def test_receipt_write_failure_after_prefix_has_no_fallback(self):
        sink = Sink(acks=[frame_length(), len(self.output), 5, OSError('sink gone')])
        code = self.run_main(sink, Clock(sv.ORIGIN))
        self.assertEqual(code, 84)
        self.assertEqual(sink.calls, 4)
        self.assertNotIn(b'"receipt_emission":"short"', bytes(sink.data))
        # boundary: the 4th call is exactly the unacknowledged receipt suffix; the sink ends at the 5-byte prefix
        self.assertEqual(sink.args[3], sink.args[2][5:])
        self.assertEqual(bytes(sink.data), sink.args[0] + self.output + sink.args[2][:5])

    def test_receipt_construction_failure_before_any_write_allows_one_short_receipt(self):
        # Complete path clock reads: preflight.start 1; scope.before 2; scope gate x2 3-4; scope.after 5;
        # four pin rows x (before, gate x2, after) 6-21; roster.before 22, roster gate x2 23-24, roster.after 25;
        # once-claim gate x2 26-27; frame.before 28, frame write gate x2 29-30; launch.before 31; wait.before 32,
        # wait timeout 33, wait.after 34; forward.before 35, forward gate x2 36-37, forward.after 38; inputs_after
        # 39-42; preserved_after 43-46; parse.before 47, parse.after 48. Cleanup reads nothing here. Then
        # receipt.before = 49 and the elapsed stamp inside construction = 50.
        sink = Sink()
        code = self.run_main(sink, Clock(sv.ORIGIN, fail_at_call=50))
        self.assertEqual(code, 84)
        receipt = last_json_line(sink)
        self.assertEqual((receipt['status'], receipt['receipt_emission']), (sv.STATUS_UNKNOWN, 'short'))
        self.assertEqual(receipt['error']['type'], 'ValueError')
        self.assertEqual(bytes(sink.data).count(b'"schema":"' + sv.RECEIPT_SCHEMA.encode()), 1)

    def test_receipt_construction_crossing_the_orchestration_cutoff_means_zero_receipt_writer_calls(self):
        # The elapsed stamp (call 50, see the count above) is the first reading past the cutoff:
        # receipt.before (49) passed, the fresh receipt.write.before check refuses, and the writer is
        # never called for the receipt.
        readings = [sv.ORIGIN] * 49 + [sv.ORIGIN + sv.ORCH_SECONDS + 0.1]
        sink = Sink()
        code = self.run_main(sink, Clock(*readings))
        self.assertEqual(code, 84)
        self.assertEqual(sink.calls, 2)                                 # frame and child bytes only
        self.assertNotIn(b'"schema":"' + sv.RECEIPT_SCHEMA.encode(), bytes(sink.data))

    def test_deadline_already_reached_means_zero_launches(self):
        sink = Sink(); child = FakeChild()
        code = self.run_main(sink, Clock(sv.ORIGIN + sv.BODY_SECONDS), child)
        self.assertEqual(code, 84)
        receipt = last_json_line(sink)
        self.assertEqual((receipt['child_invocations'], receipt['status']), (0, sv.STATUS_REFUSED))
        self.assertEqual(receipt['late_stages'][0]['stage'], 'preflight.start')
        self.assertEqual((child.kills, child.waits), (0, 0))

    def test_orchestration_cutoff_reached_before_receipt_means_writer_not_called_for_it(self):
        clock = Clock(sv.ORIGIN)
        child = FakeChild(on_poll=lambda: clock.set(sv.ORIGIN + sv.ORCH_SECONDS + 0.5))
        sink = Sink()
        code = self.run_main(sink, clock, child)
        self.assertEqual(code, 84)
        self.assertEqual(sink.calls, 2)
        self.assertNotIn(b'"schema":"' + sv.RECEIPT_SCHEMA.encode(), bytes(sink.data))

    def test_once_marker_is_claimed_before_the_child_launches(self):
        # main() creates the marker itself, once, before popen.
        events = []
        def claim(path, gate):
            events.append(('claim', path)); gate(); gate()
        child = FakeChild()
        sink = Sink()
        def run():
            return sv.main(['/r/scope.json'], now=Clock(sv.ORIGIN), writer=sink,
                           popen=lambda *a, **k: (events.append(('popen',)), child)[1],
                           collect=lambda c, d, f: self.output, open_pinned=self.files,
                           read_once=lambda path, op, gate, raw=self.scope_raw: self.files(
                               {'path': path, 'bytes': len(raw), 'mode': '0400', 'sha256': sv.digest(raw)}, gate=gate),
                           sink_check=lambda: {'dev': 1, 'ino': 7}, claim_once=claim)
        self.assertEqual(run(), 0)
        self.assertEqual(events, [('claim', '/r/.once'), ('popen',)])

    def test_used_once_marker_refuses_before_any_child(self):

        def used(path, gate):
            raise Refused('once namespace already used')
        sink = Sink(); child = FakeChild()
        self.run_main(sink, Clock(sv.ORIGIN), child, claim_once=used)
        receipt = last_json_line(sink)
        self.assertEqual(receipt['status'], sv.STATUS_REFUSED)
        self.assertIn('once namespace already used', receipt['error']['text'])
        self.assertEqual(receipt['child_invocations'], 0)

    def test_kill_crossing_the_final_cutoff_issues_no_wait(self):
        clock = Clock(sv.ORIGIN)
        child = FakeChild(alive=True, on_kill=lambda: clock.set(sv.ORIGIN + 27.5))
        def collect(c, d, f):
            clock.set(sv.ORIGIN + 26.9); d.check('read.before', d.body)
        sink = Sink()
        code = self.run_main(sink, clock, child, collect=collect)
        self.assertEqual(code, 84)
        self.assertEqual((child.kills, child.waits), (1, 0))
        receipt = last_json_line(sink)
        self.assertEqual(receipt['status'], sv.STATUS_UNKNOWN)
        self.assertIn('no wait issued', receipt['termination'])
        self.assertTrue(any(s['stage'] == 'wait.skipped' for s in receipt['late_stages']))

    def test_live_child_at_final_cutoff_gets_no_late_kill(self):
        clock = Clock(sv.ORIGIN)
        child = FakeChild(alive=True)
        def collect(c, d, f):
            clock.set(sv.ORIGIN + 27.0); d.check('read.before', d.body)
        sink = Sink()
        code = self.run_main(sink, clock, child, collect=collect)
        self.assertEqual(code, 84)
        self.assertEqual((child.kills, child.waits), (0, 0))
        receipt = last_json_line(sink)
        self.assertIn('no late termination issued', receipt['termination'])
        self.assertTrue(any(s['stage'] == 'termination.skipped' for s in receipt['late_stages']))

    def test_last_close_returning_after_the_final_cutoff_is_non_pass(self):
        clock = Clock(sv.ORIGIN)
        def collect(c, d, f):
            f.acquire('child_stdout', Handle(on_close=lambda: clock.set(sv.ORIGIN + 27.5)))   # the only handle
            return self.output
        sink = Sink()
        code = self.run_main(sink, clock, collect=collect)
        self.assertEqual(code, 84)
        receipt = last_json_line(sink)
        self.assertEqual(receipt['finalizers'], {'child_stdout': 'closed_late'})
        self.assertEqual(receipt['status'], sv.STATUS_UNKNOWN)
        self.assertEqual(receipt['error']['text'], 'a close returned after the final cutoff')

    def test_scope_or_roster_file_changed_between_reads_is_never_parsed(self):
        other = json.dumps({'module': 'x', 'expected_full_ids': ['x.C.test_a'], 'class_counts': {'C': 1}, 'top_level_count': 1}).encode()
        files = Files(self.files.store, later={'/r/roster.json': other})
        sink = Sink()
        code = self.run_main(sink, Clock(sv.ORIGIN), files=files)
        self.assertEqual(code, 0)
        receipt = last_json_line(sink)
        self.assertEqual(files.reads['/r/roster.json'], 1)
        self.assertEqual(receipt['roster']['count'], 27)
        self.assertEqual(receipt['roster']['consumed_sha256'], sv.digest(self.roster_raw))

    def test_pin_mismatch_or_type_trap_refuses_before_launch(self):
        child = FakeChild()
        for mutate in (lambda s: s['roster_pin'].__setitem__('sha256', HEX0), lambda s: s['roster_pin'].__setitem__('bytes', 1.0),
                       lambda s: s['inputs'][0].__setitem__('bytes', True), lambda s: s['timeout_pin'].__setitem__('mode', '0644')):
            with self.subTest():
                scope = json.loads(self.scope_raw); mutate(scope); raw = json.dumps(scope).encode()
                files = Files(dict(self.files.store, **{'/r/scope.json': (raw, '0400')}))
                sink = Sink()
                code = self.run_main(sink, Clock(sv.ORIGIN), child, files=files,
                                     read_once=lambda path, op, gate, raw=raw: raw)
                self.assertEqual(code, 84)
                self.assertEqual(last_json_line(sink)['child_invocations'], 0)
        self.assertEqual((child.kills, child.waits), (0, 0))

    def test_primary_failure_retained_with_bounded_secondary_cleanup_outcomes(self):
        class Grumpy(FakeChild):
            def poll(self):
                self.polls += 1
                raise OSError('poll failed')
        child = Grumpy(); sink = Sink()
        code = self.run_main(sink, Clock(sv.ORIGIN), child, output=terminal_for(self.ids[:26]))
        self.assertEqual(code, 84)
        receipt = last_json_line(sink)
        self.assertEqual(receipt['error']['type'], 'Refused')
        self.assertIn('terminal line count', receipt['error']['text'])
        self.assertEqual(receipt['secondary']['poll']['type'], 'OSError')
        self.assertEqual(receipt['status'], sv.STATUS_UNKNOWN)
        self.assertTrue(set(receipt['secondary']) <= set(sv.SECONDARY_STAGES) | {'other'})

    def test_pinned_read_primary_with_close_secondary_reaches_the_receipt(self):
        e1 = OSError('fstat E1'); e1.__secondary_close__ = {'type': 'OSError', 'text': 'close E2'}
        def failing(row, ops=None, gate=sv._no_gate):
            raise e1
        sink = Sink()
        code = self.run_main(sink, Clock(sv.ORIGIN), files=failing,
                             read_once=lambda path, op, gate, raw=self.scope_raw: raw)
        self.assertEqual(code, 84)
        receipt = last_json_line(sink)
        self.assertEqual((receipt['error']['type'], receipt['error']['text']), ('OSError', 'fstat E1'))
        self.assertEqual(receipt['secondary']['close']['text'], 'close E2')
        self.assertEqual(receipt['child_invocations'], 0)

    def test_exhausted_clock_at_receipt_check_never_escapes_and_writes_nothing(self):
        broken = iter([sv.ORIGIN])
        sink = Sink()
        code = sv.main([], now=lambda: next(broken), writer=sink)
        self.assertEqual(code, 84)
        self.assertEqual(len(sink.data), 0)


class GateCounter:
    """A gate that counts calls and raises Refused from call number `late_at` onwards."""
    def __init__(self, late_at=None):
        self.calls = 0; self.late_at = late_at
    def __call__(self):
        self.calls += 1
        if self.late_at is not None and self.calls >= self.late_at:
            raise Refused('deadline reached: gate call %d' % self.calls)


class P2AdjacentCheckTests(unittest.TestCase):
    """adjacent checks around select/read, after open/stat, after a successful close."""

    def row(self, content=b'data'):
        return {'path': '/p/f', 'bytes': len(content), 'mode': '0400', 'sha256': sv.digest(content)}

    def test_late_open_means_no_stat_no_read_and_no_late_close(self):
        # gate calls in open_pinned: 1 before open, 2 post-open (inside the boundary), 3 after stat, then per
        # read before/after, then before close, then after close. A clock that is late from call 2 onwards
        # models an open that returned after the cutoff: the stat-dependent read never starts, and the
        # close is not permitted either (an unpermitted late action is skipped, recorded as the bounded
        # secondary close fact, never issued "to report lateness").
        ops = FakeOps(b'data'); gate = GateCounter(late_at=2)
        with self.assertRaises(Refused) as caught:
            sv.open_pinned(self.row(), ops=ops, gate=gate)
        self.assertEqual((ops.opens, ops.reads, ops.closes), (1, 0, 0))
        self.assertEqual(gate.calls, 3)                                     # 2 raised (primary), 3 raised (close not permitted)
        self.assertEqual(getattr(caught.exception, '__secondary_close__', None)['type'], 'Refused')

    def test_stat_crossing_means_no_subsequent_read(self):
        ops = FakeOps(b'data'); gate = GateCounter(late_at=3)             # the check right after stat refuses
        with self.assertRaises(Refused):
            sv.open_pinned(self.row(), ops=ops, gate=gate)
        self.assertEqual((ops.reads, ops.closes), (0, 0))                 # no read; late close not permitted

    def test_successful_close_crossing_is_a_refusal_without_a_second_close(self):
        ops = FakeOps(b'data')
        # gate calls: 1 before open, 2 post-open, 3 after stat, 4 before read, 5 after read, 6 before 2nd read,
        # 7 after 2nd read, 8 before close, 9 after the successful close -> late
        gate = GateCounter(late_at=9)
        with self.assertRaises(Refused):
            sv.open_pinned(self.row(), ops=ops, gate=gate)
        self.assertEqual(ops.closes, 1)                                   # the one close happened; never a second

    def test_post_close_lateness_never_replaces_a_primary_body_error(self):
        e1 = OSError('read E1'); ops = FakeOps(read_error=e1)
        gate = GateCounter(late_at=6)                                      # the check after the close refuses
        with self.assertRaises(OSError) as caught:
            sv.open_pinned(self.row(), ops=ops, gate=gate)
        self.assertIs(caught.exception, e1)                               # primary preserved
        self.assertEqual(getattr(e1, '__secondary_close__', None)['type'], 'Refused')   # lateness as bounded secondary
        self.assertEqual(ops.closes, 1)

    def test_late_select_return_starts_no_read(self):
        class FakeKey:
            def __init__(self, fobj):
                self.fileobj = fobj
        class FakeSelector:
            def __init__(self, clock):
                self.clock = clock; self.registered = True; self.selects = 0
            def register(self, fobj, events):
                pass
            def unregister(self, fobj):
                self.registered = False
            def get_map(self):
                return {1: None} if self.registered else {}
            def select(self, timeout):
                self.selects += 1
                self.clock.set(sv.ORIGIN + sv.BODY_SECONDS + 0.1)        # select returns late
                return [FakeKey(self.stdout)]
            def close(self):
                pass
        class FakeStdout:
            def __init__(self):
                self.reads = 0
            def fileno(self):
                return 7
            def close(self):
                pass
        clock = Clock(sv.ORIGIN); d = sv.Deadlines(sv.ORIGIN, clock); f = sv.Finalizers()
        stdout = FakeStdout(); child = FakeChild(); child.stdout = stdout
        sel = FakeSelector(clock); sel.stdout = stdout
        reads = {'n': 0}
        def fake_read(fd, n):
            reads['n'] += 1; return b'x'
        with self.assertRaises(Refused):
            sv.collect_child_output(child, d, f, selector_factory=lambda: sel, read=fake_read,
                                    set_blocking=lambda fd, b: None)   # seams; no module globals patched
        self.assertEqual((sel.selects, reads['n']), (1, 0))               # late select return: zero reads
        self.assertEqual(d.late[0]['stage'], 'select.after')
        self.assertEqual(f.outcomes['child_stdout'], 'acquired')          # ownership registered; cleanup is the caller's


class PartialChildOutputTests(unittest.TestCase):
    """output read before a refusal is kept and forwarded by cleanup, not dropped."""

    def test_collect_attaches_partial_output_to_the_refusal(self):
        class FakeKey:
            def __init__(self, fobj):
                self.fileobj = fobj
        class FakeSelector:
            def __init__(self, clock, stdout):
                self.clock = clock; self.stdout = stdout; self.selects = 0
            def register(self, fobj, events):
                pass
            def unregister(self, fobj):
                pass
            def get_map(self):
                return {1: None}
            def select(self, timeout):
                self.selects += 1
                if self.selects == 2:
                    self.clock.set(sv.ORIGIN + sv.BODY_SECONDS + 0.1)    # the child stalls: the second select is late
                return [(FakeKey(self.stdout), 1)]
            def close(self):
                pass
        class FakeStdout:
            def fileno(self):
                return 7
            def close(self):
                pass
        clock = Clock(sv.ORIGIN); d = sv.Deadlines(sv.ORIGIN, clock); f = sv.Finalizers()
        stdout = FakeStdout(); child = FakeChild(); child.stdout = stdout
        with self.assertRaises(Refused) as caught:
            sv.collect_child_output(child, d, f, selector_factory=lambda: FakeSelector(clock, stdout),
                                    read=lambda fd, n: b'abc', set_blocking=lambda fd, b: None)
        self.assertEqual(caught.exception.partial_child_output, b'abc')

    def _collect(self, clock, read):
        class FakeKey:
            def __init__(self, fobj):
                self.fileobj = fobj
        class FakeSelector:
            def __init__(self, stdout):
                self.stdout = stdout
            def register(self, fobj, events):
                pass
            def unregister(self, fobj):
                pass
            def get_map(self):
                return {1: None}
            def select(self, timeout):
                return [(FakeKey(self.stdout), 1)]
            def close(self):
                pass
        class FakeStdout:
            def fileno(self):
                return 7
            def close(self):
                pass
        d = sv.Deadlines(sv.ORIGIN, clock); f = sv.Finalizers()
        child = FakeChild(); child.stdout = FakeStdout()
        return lambda c=child, dl=d, fz=f: sv.collect_child_output(c, dl, fz, selector_factory=lambda: FakeSelector(c.stdout),
                                                                     read=read, set_blocking=lambda fd, b: None)

    def test_bytes_from_a_read_that_returns_after_the_deadline_are_kept(self):
        # QA-1: the read crosses the body deadline and returns 3 bytes; the refusal at read.after carries them.
        clock = Clock(sv.ORIGIN)
        def late_read(fd, n):
            clock.set(sv.ORIGIN + sv.BODY_SECONDS + 0.1)
            return b'abc'
        with self.assertRaises(Refused) as caught:
            self._collect(clock, late_read)()
        self.assertEqual(caught.exception.partial_child_output, b'abc')

    def test_the_permitted_prefix_of_an_overflowing_read_is_kept(self):
        # QA-1: 12 reads of 4000 bytes (48000), then a read of 1153 bytes where 1152 fit: the refusal carries
        # exactly CHILD_CAP bytes (the permitted prefix), not the 48000 read before the overflowing chunk.
        clock = Clock(sv.ORIGIN)
        with self.assertRaisesRegex(Refused, 'child output cap exceeded') as caught:
            self._collect(clock, lambda fd, n: b'x' * min(n, 4000))()
        self.assertEqual(len(caught.exception.partial_child_output), sv.CHILD_CAP)

    def test_main_forwards_bytes_from_a_late_read(self):
        # QA-1 forwarding/receipt: the late-read bytes reach the sink once and the receipt counts them.
        roster_raw = ROSTER_PATH.read_bytes()
        scope_raw, files = build_scope_and_files(roster_raw)
        clock = Clock(sv.ORIGIN)
        def late_read(fd, n):
            clock.set(sv.ORIGIN + sv.BODY_SECONDS + 0.1)
            return b'late!'
        def collect(c, d, f):
            stdout = type('S', (), {'fileno': lambda self: 7, 'close': lambda self: None})()
            c.stdout = stdout
            key = type('K', (), {'fileobj': stdout})()
            sel = type('Sel', (), {'register': lambda self, o, e: None, 'unregister': lambda self, o: None,
                                   'get_map': lambda self: {1: None}, 'select': lambda self, t: [(key, 1)],
                                   'close': lambda self: None})()
            return sv.collect_child_output(c, d, f, selector_factory=lambda: sel, read=late_read,
                                           set_blocking=lambda fd, b: None)
        def read_once(path, op, gate, raw=scope_raw):
            return files({'path': path, 'bytes': len(raw), 'mode': '0400', 'sha256': sv.digest(raw)}, gate=gate)
        sink = Sink()
        sv.main(['/r/scope.json'], now=clock, writer=sink, popen=lambda *a, **k: FakeChild(), collect=collect,
                open_pinned=files, read_once=read_once, sink_check=lambda: {'dev': 1, 'ino': 7}, claim_once=lambda p, g: None)
        receipt = json_suffix_at(sink, frame_length() + len(b'late!'))
        self.assertNotEqual(receipt['status'], sv.STATUS_COMPLETE)
        self.assertEqual((receipt['child_emission'], receipt['child_bytes']), ('completed', 5))
        self.assertEqual(bytes(sink.data).count(b'late!'), 1)

    def test_main_forwards_partial_output_after_a_collect_refusal(self):
        roster_raw = ROSTER_PATH.read_bytes()
        scope_raw, files = build_scope_and_files(roster_raw)
        def collect(c, d, f):
            error = Refused('child stalled'); error.partial_child_output = b'partial'
            raise error
        def read_once(path, op, gate, raw=scope_raw):
            return files({'path': path, 'bytes': len(raw), 'mode': '0400', 'sha256': sv.digest(raw)}, gate=gate)
        sink = Sink()
        sv.main(['/r/scope.json'], now=Clock(sv.ORIGIN), writer=sink, popen=lambda *a, **k: FakeChild(), collect=collect,
                open_pinned=files, read_once=read_once, sink_check=lambda: {'dev': 1, 'ino': 7}, claim_once=lambda p, g: None)
        receipt = json_suffix_at(sink, frame_length() + len(b'partial'))   # preflight frame, forwarded bytes, receipt
        self.assertEqual(receipt['status'], sv.STATUS_REFUSED)
        self.assertEqual((receipt['child_emission'], receipt['child_bytes']), ('completed', 7))
        self.assertEqual(receipt['child_sha256'], sv.digest(b'partial'))
        self.assertIn(b'partial', bytes(sink.data))


class ExternalAcceptanceModelTests(unittest.TestCase):
    """The external observer's predicate, modelled as data: internal COMPLETE is never sufficient."""

    def accept(self, outer_rc, receipt_line, sink_size, timely):
        """Model of RUN PROPOSAL section 4: a pure function over externally observed facts."""
        if outer_rc != 0 or not timely or sink_size > sv.AGGREGATE_CAP:
            return 'REFUSED'
        try:
            receipt = json.loads(receipt_line)
        except ValueError:
            return 'UNKNOWN'
        if receipt.get('status') != sv.STATUS_COMPLETE or receipt.get('receipt_emission') != 'prepared':
            return 'REFUSED'
        return 'PASS'

    def test_internal_complete_with_partial_capture_or_bad_outer_exit_is_not_pass(self):
        good = json.dumps({'status': sv.STATUS_COMPLETE, 'receipt_emission': 'prepared'})
        self.assertEqual(self.accept(0, good, 1000, True), 'PASS')
        self.assertEqual(self.accept(84, good, 1000, True), 'REFUSED')
        self.assertEqual(self.accept(None, good, 1000, True), 'REFUSED')
        self.assertEqual(self.accept(0, good[:-3], 1000, True), 'UNKNOWN')          # partial capture
        self.assertEqual(self.accept(0, good, 1000, False), 'REFUSED')              # late completion
        self.assertEqual(self.accept(0, good, sv.AGGREGATE_CAP + 1, True), 'REFUSED')
        self.assertEqual(self.accept(0, json.dumps({'status': sv.STATUS_COMPLETE, 'receipt_emission': 'completed'}), 1000, True), 'REFUSED')


if __name__ == '__main__':
    unittest.main()
