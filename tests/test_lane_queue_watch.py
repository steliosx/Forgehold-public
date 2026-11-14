"""Queue, watcher and validator unit tests using temporary files; no network or child process."""
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

LANE = Path(__file__).resolve().parents[1] / 'lane'


def load(name):
    spec = importlib.util.spec_from_file_location('lane_' + name, LANE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


Q = load('fh_queue')
W = load('fh_watch')


class HaltedHoldsTests(unittest.TestCase):
    """the watcher and the queue apply the same hold rule."""

    def test_missing_holds_folder_is_a_hold(self):
        with tempfile.TemporaryDirectory() as qd:
            self.assertIn('holds missing', W.halted(qd))

    def test_holds_that_is_a_file_or_symlink_is_a_hold(self):
        with tempfile.TemporaryDirectory() as qd:
            Path(qd, 'holds').write_text('x')
            self.assertIn('not a plain directory', W.halted(qd))
        with tempfile.TemporaryDirectory() as qd:
            os.mkdir(os.path.join(qd, 'real'))
            os.symlink(os.path.join(qd, 'real'), os.path.join(qd, 'holds'))
            self.assertIn('not a plain directory', W.halted(qd))

    def test_empty_holds_folder_is_clear_and_an_entry_is_a_hold(self):
        with tempfile.TemporaryDirectory() as qd:
            os.mkdir(os.path.join(qd, 'holds'))
            self.assertIsNone(W.halted(qd))
            Path(qd, 'holds', 'example-project-1.json').write_text('{}')
            self.assertIn('hold present', W.halted(qd))


class PrefixRefTests(unittest.TestCase):
    """a ref that git refuses never passes the allowlist prefix match."""

    KEY = ('example-project', None, 'forgehold-reference-guard.yml', 'forgehold-reference-guard')

    def setUp(self):
        self.al = Q.allowlist(str(LANE))

    def key(self, ref):
        return (self.KEY[0], ref, self.KEY[2], self.KEY[3])

    def test_git_invalid_ref_parts_refuse(self):
        for ref in ('review/fix.lock/x', 'review/x.lock', 'review/x.'):
            with self.subTest(ref=ref):
                with self.assertRaises(ValueError):
                    Q.match(self.al, self.key(ref))

    def test_ordinary_prefix_ref_is_accepted(self):
        # review/x./y is a valid git branch name (an interior part may end in "."; QA-3).
        for ref in ('review/fix-lock.v2', 'review/x./y'):
            with self.subTest(ref=ref):
                self.assertEqual(Q.match(self.al, self.key(ref))['ref_prefix'], 'review/')


class SelectReadErrorTests(unittest.TestCase):
    """a read error leaves the request in requests/ and is not recorded as invalid."""

    @unittest.skipIf(os.geteuid() == 0, 'root can read a 0000 file')
    def test_unreadable_request_is_not_moved_to_rejected(self):
        with tempfile.TemporaryDirectory() as qd:
            os.mkdir(os.path.join(qd, 'requests'))
            name = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-unit.json'
            path = os.path.join(qd, 'requests', name)
            Path(path).write_text('{}')
            os.chmod(path, 0)
            try:
                with self.assertRaises(OSError):
                    Q.cmd_select(qd, str(LANE))
                self.assertTrue(os.path.exists(path))
                self.assertFalse(os.path.exists(os.path.join(qd, 'rejected')))
            finally:
                os.chmod(path, 0o600)


if __name__ == '__main__':
    unittest.main()
