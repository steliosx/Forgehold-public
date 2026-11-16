"""render_packet.py tests with a synthetic config in temporary directories; nothing is installed or run."""
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import stat
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lane_render_packet', REPO / 'lane' / 'render_packet.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

VALUES = {
    'FH_QUEUE_DIR': '/srv/fh/queue', 'FH_INPUT_DIR': '/srv/fh/lane-input', 'FH_HOST_LOCK': '/srv/fh/host-heavy.lock',
    'FH_EVIDENCE_ROOT': '/srv/fh/evidence', 'FH_PILOT_DIR': '/srv/fh/pilot', 'FH_OPERATOR_HOME': '/srv/fh/operator',
    'FH_MAILBOX_DIR': '/srv/fh/reviewer-mailbox/messages', 'FH_MARKER_FILE': '/srv/fh/authority/owner.json',
    'FH_APP_KEY_FILE': '/srv/fh/operator/.config/forgehold-key/github-app-1.pem',
    'FH_INPUT_ANCESTORS': '/srv /srv/fh', 'FH_APP_KEY_ANCESTORS': '/srv/fh/operator/.config /srv/fh/operator/.config/forgehold-key',
    'FH_MARKER_SHA256': 'a' * 64, 'FH_PACK_NAME': 'preloop-example-image', 'FH_PACK_SHA256': 'b' * 64,
    'FH_PIN_PRELOOP': 'c' * 64, 'FH_PIN_RUNNER': 'd' * 64, 'FH_PIN_REAL': 'e' * 64, 'FH_PIN_SMOLVM_BIN': 'f' * 64,
    'FH_PIN_LIBKRUN': '0' * 64, 'FH_PIN_LIBKRUNFW': '1' * 64, 'FH_ENGINE_TOKEN_REF': 'engine-token-' + '2' * 64,
    'FH_OWNER': 'example-owner', 'FH_REVIEWER_ID': 'example-reviewer', 'FH_OPERATOR_ID': 'example-operator',
    'FH_OPERATOR_LABEL': 'example operator', 'FH_REVIEWER_KEY_ID': '0123456789ABCDEF',
    'FH_REVIEWER_PUBKEY': 'RW' + 'A' * 54, 'FH_APP_ID': '1',
}
WATCH = {'schema': 'FH_QUEUE_WATCH_1', 'entries': [], 'window': 'synthetic', 'policy': 'synthetic'}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.tree = os.path.join(self.tmp, 'tree')
        for part in ('lane', 'examples/deployment'):
            shutil.copytree(REPO / part, os.path.join(self.tree, part))
        self.cfg = os.path.join(self.tmp, 'cfg')
        os.mkdir(self.cfg)
        self.write_config(VALUES)
        shutil.copy(REPO / 'lane' / 'ALLOWLIST.json', os.path.join(self.cfg, 'ALLOWLIST.json'))
        self.write_json('WATCH.json', WATCH)
        self.parent = os.path.join(self.tmp, 'packets')
        os.mkdir(self.parent)
        self.out = os.path.join(self.parent, 'b3-lane-99')

    def tearDown(self):
        for root, dirs, _ in os.walk(self.tmp):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o700)
        shutil.rmtree(self.tmp)

    def write_json(self, name, data):
        with open(os.path.join(self.cfg, name), 'w') as f:
            json.dump(data, f)

    def write_config(self, values):
        self.write_json('config.json', {'schema': R.SCHEMA, 'values': values})

    def refused(self, pattern):
        before = sorted(os.listdir(self.parent))
        with self.assertRaisesRegex(R.Refused, pattern):
            R.render(self.tree, self.cfg, self.out)
        self.assertFalse(os.path.lexists(self.out))
        self.assertEqual(sorted(os.listdir(self.parent)), before)


class RenderTests(Fixture):
    def test_render_writes_a_verified_read_only_packet(self):
        record, manifest = R.render(self.tree, self.cfg, self.out)
        names = [p for p, _, _ in R.FILES] + ['RENDER.json']
        self.assertEqual(sorted(os.listdir(self.out)), sorted(names + ['SHA256SUMS']))
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o500)
        sums = Path(self.out, 'SHA256SUMS').read_bytes()
        self.assertEqual(hashlib.sha256(sums).hexdigest(), manifest)
        self.assertEqual([line.split('  ')[1] for line in sums.decode().splitlines()], names)
        for line in sums.decode().splitlines():
            digest, name = line.split('  ')
            data = Path(self.out, name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.out, name)).st_mode), 0o400)
            self.assertNotIn(b'@@', data)
            self.assertNotIn(b'INACTIVE PUBLIC REFERENCE', data)
            self.assertNotIn(b'/nonexistent/', data)
        queue = Path(self.out, 'forgehold-queue.service').read_text()
        self.assertIn('ExecStart=/usr/bin/bash %s/queue_run.sh' % self.out, queue)
        self.assertIn('Forgehold standing queue b3-lane-99', queue)
        self.assertEqual(record['source_commit'], None)
        self.assertEqual(record['tokens'], sorted(R.TOKENS))
        self.assertEqual(json.loads(Path(self.out, 'RENDER.json').read_text()), record)

    def test_same_inputs_give_the_same_bytes(self):
        R.render(self.tree, self.cfg, self.out)
        first = {n: Path(self.out, n).read_bytes() for n in os.listdir(self.out)}
        os.chmod(self.out, 0o700)
        shutil.rmtree(self.out)
        R.render(self.tree, self.cfg, self.out)
        self.assertEqual({n: Path(self.out, n).read_bytes() for n in os.listdir(self.out)}, first)

    def test_public_deployment_files_keep_their_guards(self):
        for _, src, kind in R.FILES:
            if kind in ('sh', 'unit'):
                lines = (REPO / src).read_text().split('\n')
                if kind == 'sh':
                    self.assertEqual(lines[1:4], R.SH_GUARD, src)
                else:
                    self.assertEqual((lines[0], lines[2]), R.UNIT_GUARD, src)


class RefusalTests(Fixture):
    def test_missing_and_unknown_values_refuse(self):
        values = dict(VALUES)
        del values['FH_APP_ID']
        self.write_config(values)
        self.refused('missing')
        self.write_config(dict(VALUES, FH_EXTRA='/x'))
        self.refused('unknown')

    def test_bad_values_refuse(self):
        for name, value in (('FH_QUEUE_DIR', 'srv/fh/queue'), ('FH_QUEUE_DIR', '/srv/../queue'),
                            ('FH_QUEUE_DIR', '/srv/fh queue'), ('FH_EVIDENCE_ROOT', '/srv/fh.d/evidence'),
                            ('FH_MARKER_SHA256', 'A' * 64), ('FH_REVIEWER_PUBKEY', 'RW' + 'A' * 53),
                            ('FH_OPERATOR_LABEL', 'example "operator"'), ('FH_REVIEWER_ID', 'a.b'),
                            ('FH_APP_ID', '0')):
            with self.subTest(name=name, value=value):
                self.write_config(dict(VALUES, **{name: value}))
                self.refused('not a valid')

    def test_unknown_token_in_a_source_refuses(self):
        with open(os.path.join(self.tree, 'lane', 'fh_queue.py'), 'a') as f:
            f.write('# @@FH_NOT_A_TOKEN@@\n')
        self.refused('unknown token FH_NOT_A_TOKEN')

    def test_missing_guard_refuses(self):
        path = os.path.join(self.tree, 'examples', 'deployment', 'queue_run.sh.example')
        lines = Path(path).read_text().split('\n')
        Path(path).write_text('\n'.join(lines[:3] + lines[4:]))
        self.refused('guard missing')

    def test_existing_output_or_git_parent_refuses(self):
        os.mkdir(self.out)
        self.refused_existing()
        os.rmdir(self.out)
        os.mkdir(os.path.join(self.parent, '.git'))
        self.refused('inside a git work tree')

    def refused_existing(self):
        with self.assertRaisesRegex(R.Refused, 'packet directory exists'):
            R.render(self.tree, self.cfg, self.out)

    def test_watch_entry_must_be_in_the_allowlist(self):
        self.write_json('WATCH.json', dict(WATCH, entries=[{'repository': 'nope', 'ref': 'main', 'workflow': 'x.yml',
                                                            'job': 'j', 'mode': 'daily'}]))
        self.refused('not in ALLOWLIST.json')

    def test_symlinked_config_refuses(self):
        real = os.path.join(self.tmp, 'config.json')
        os.rename(os.path.join(self.cfg, 'config.json'), real)
        os.symlink(real, os.path.join(self.cfg, 'config.json'))
        with self.assertRaises(OSError):
            R.render(self.tree, self.cfg, self.out)
        self.assertFalse(os.path.lexists(self.out))



class FakeOps:
    """os with chosen calls replaced (fault injection for publish/verify)."""
    def __init__(self, **calls):
        self.__dict__.update(calls)

    def __getattr__(self, name):
        return getattr(os, name)


class PublicationFaultTests(Fixture):
    def render(self, ops):
        return R.render(self.tree, self.cfg, self.out, ops=ops)

    def assert_refused_clean(self, ops, pattern):
        with self.assertRaisesRegex(R.Refused, pattern):
            self.render(ops)
        self.assertFalse(os.path.lexists(self.out))
        self.assertEqual(os.listdir(self.parent), [])

    def test_short_writes_still_give_a_verified_packet(self):
        _, manifest = self.render(FakeOps(write=lambda fd, data: os.write(fd, bytes(data[:7]))))
        sums = Path(self.out, 'SHA256SUMS').read_bytes()
        self.assertEqual(hashlib.sha256(sums).hexdigest(), manifest)
        for line in sums.decode().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256(Path(self.out, name).read_bytes()).hexdigest(), digest)

    def test_zero_progress_refuses_and_leaves_nothing(self):
        self.assert_refused_clean(FakeOps(write=lambda fd, data: 0), 'no progress')

    def test_a_later_write_error_refuses_and_leaves_nothing(self):
        count = []
        def write(fd, data):
            count.append(1)
            if len(count) == 6:
                raise OSError(5, 'injected I/O error')
            return os.write(fd, data)
        self.assert_refused_clean(FakeOps(write=write), 'injected I/O error')

    def test_a_write_that_reports_more_than_it_wrote_is_caught_by_the_readback(self):
        def write(fd, data):
            os.write(fd, bytes(data[:max(1, len(data) // 2)]))
            return len(data)
        self.assert_refused_clean(FakeOps(write=write), 'differs from the manifest')

    def test_a_competing_destination_is_refused_and_preserved(self):
        def mkdir(path, mode):
            os.mkdir(path)
            Path(path, 'foreign.txt').write_text('not ours')
            return os.mkdir(path, mode)
        with self.assertRaisesRegex(R.Refused, 'packet directory exists'):
            self.render(FakeOps(mkdir=mkdir))
        self.assertEqual(Path(self.out, 'foreign.txt').read_text(), 'not ours')

    def test_a_final_mode_failure_leaves_nothing(self):
        def chmod(path, mode):
            if path == self.out and mode == 0o500:
                raise PermissionError(1, 'injected chmod failure')
            return os.chmod(path, mode)
        self.assert_refused_clean(FakeOps(chmod=chmod), 'injected chmod failure')

    def test_a_foreign_file_in_the_output_is_retained_and_reported(self):
        opened = []
        def open_(path, flags, mode=0o777):
            if flags & os.O_CREAT:
                opened.append(path)
                if len(opened) == 3:
                    Path(self.out, 'foreign.txt').write_text('not ours')
                if len(opened) == 5:
                    raise OSError(5, 'injected open failure')
            return os.open(path, flags, mode)
        with self.assertRaisesRegex(R.Refused, 'output retained at'):
            self.render(FakeOps(open=open_))
        self.assertEqual(Path(self.out, 'foreign.txt').read_text(), 'not ours')
        self.assertEqual(os.listdir(self.out), ['foreign.txt'])

    def test_a_fifo_input_refuses_promptly(self):
        os.unlink(os.path.join(self.cfg, 'config.json'))
        os.mkfifo(os.path.join(self.cfg, 'config.json'))
        old = signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError('blocked on a FIFO')))
        signal.alarm(5)
        try:
            self.assert_refused_clean(os, 'not a bounded regular file')
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)


if __name__ == '__main__':
    unittest.main()
