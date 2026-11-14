"""Additional model tests for strict types, local bindings and refused live effects."""
import copy
import json
import unittest

from forgehold_b1.data_rules import digest, encode, Refused
from forgehold_b1 import quality_job as adapter
from tests.test_quality_job import ModelRegistry, binding, expected, model_digest, ROOT


def raw_report(row):
    """Compact canonical bytes for a crafted report; the pin in expected() follows the bytes."""
    return json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False,
                      ensure_ascii=True).encode('utf-8')


class SuccessorQualityRefusalTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / 'fixtures/quality-run.MODEL_ONLY.json').read_bytes()
        self.report = json.loads(self.raw)
        self.expected = expected(self.raw)

    def refuses(self, row, reason=None):
        raw = raw_report(row)
        if reason is None:
            with self.assertRaises(Refused):
                adapter.interpret_quality(raw, expected(raw))
        else:   
            with self.assertRaisesRegex(Refused, reason):
                adapter.interpret_quality(raw, expected(raw))

    def test_wrong_check_name_in_the_right_position_refuses(self):
        for index in range(4):
            for wrong in ('ruff-infra', 'RUFF', 'pip check', ''):
                with self.subTest(index=index, wrong=wrong):
                    row = copy.deepcopy(self.report)
                    row['checks'][index]['name'] = wrong
                    self.refuses(row)

    def test_extra_or_missing_key_inside_a_check_row_refuses(self):
        for index in range(4):
            with self.subTest(index=index, variant='extra'):
                row = copy.deepcopy(self.report)
                row['checks'][index]['note'] = 'x'
                self.refuses(row)
            for missing in ('name', 'status', 'exit_code'):
                with self.subTest(index=index, variant='missing ' + missing):
                    row = copy.deepcopy(self.report)
                    del row['checks'][index][missing]
                    self.refuses(row)

    def test_exit_zero_with_non_pass_status_refuses(self):
        for index in range(4):
            for status in ('FAIL', 'pass', 'Pass', 'PASSED', 'OK'):
                with self.subTest(index=index, status=status):
                    row = copy.deepcopy(self.report)
                    row['checks'][index]['status'] = status  # exit_code stays literal 0
                    self.refuses(row)

    def test_report_status_case_variants_refuse(self):
        for status in ('pass', 'Pass', 'PASSED', 'OK', 'PASS '):
            with self.subTest(status=status):
                self.refuses(dict(self.report, status=status))

    def test_reason_key_with_pass_status_refuses(self):
        # run_quality.py adds 'reason' only on failure; a PASS report carrying it is malformed.
        self.refuses(dict(self.report, reason=None))
        self.refuses(dict(self.report, reason='TimeoutExpired'))

    def test_report_json_depth_overflow_refuses_before_schema(self):
        nested = 'x'
        for _ in range(17):
            nested = [nested]
        self.refuses(dict(self.report, tools=nested), 'JSON depth')

    def test_report_json_node_count_overflow_refuses_before_schema(self):
        self.refuses(dict(self.report, tools=list(range(9000))), 'JSON node count')

    def test_pinned_report_that_is_not_json_or_not_utf8_refuses(self):

        for raw, reason in ((b'nul', 'malformed JSON'), (b'\xff', 'JSON not UTF-8')):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(Refused, reason):
                    adapter.interpret_quality(raw, expected(raw))

    def test_lock_pin_bytes_type_or_range_in_expected_binding_refuses(self):
        for name in adapter.lock_pins():
            for value in (True, False, 0, -1, 65537, '862', 862.0, None):
                with self.subTest(name=name, value=value):
                    bad = copy.deepcopy(self.expected)
                    bad['lock_pins'][name]['bytes'] = value
                    with self.assertRaises(Refused):
                        adapter.interpret_quality(self.raw, bad)

    def test_quality_report_pin_bytes_type_or_range_refuses(self):
        for value in (True, 0, 65537, str(len(self.raw)), None):
            with self.subTest(value=value):
                bad = copy.deepcopy(self.expected)
                bad['quality_report_pin']['bytes'] = value
                with self.assertRaises(Refused):
                    adapter.interpret_quality(self.raw, bad)

    def test_maximum_quality_seconds_type_or_range_refuses(self):
        for value in (0, 331, True, 330.0, '330', None):
            with self.subTest(value=value):
                bad = dict(self.expected, maximum_quality_seconds=value)
                with self.assertRaises(Refused):
                    adapter.interpret_quality(self.raw, bad)

    def test_code_digests_extra_or_missing_scope_refuses(self):
        row = copy.deepcopy(self.report)
        row['code_digests']['workflow'] = adapter.WORKFLOW_SHA256
        self.refuses(row)
        row = copy.deepcopy(self.report)
        del row['code_digests']['harness']
        self.refuses(row)

    def test_scope_text_variant_refuses(self):
        self.refuses(dict(self.report, scope=adapter.REPORT_SCOPE.lower()))
        self.refuses(dict(self.report, scope=adapter.REPORT_SCOPE + ' '))


class SuccessorJobRefusalTests(unittest.TestCase):
    def setUp(self):
        self.registry = ModelRegistry()
        self.binding = binding(self.registry)

    def test_oversized_profile_or_inventory_bytes_refuse(self):
        # Adapter :76-81 is one combined predicate (bytes type, 0 < len <= cap, digest == pin);
        # the length bound is its first false term here. The pin would also fail; the test
        # cannot distinguish the two by the exception alone.
        for key, limit in (('profile_raw', 32768), ('inventory_raw', 65536)):
            with self.subTest(key=key):
                bad = dict(self.binding)
                bad[key] = self.binding[key] + b' ' * (limit + 1)
                with self.assertRaises(Refused):
                    adapter.prepare_job(bad, self.registry)
        self.assertEqual(self.registry.live_calls, 0)

    def test_empty_profile_or_inventory_bytes_refuse(self):
        for key in ('profile_raw', 'inventory_raw'):
            with self.subTest(key=key):
                bad = dict(self.binding)
                bad[key] = b''
                with self.assertRaises(Refused):
                    adapter.prepare_job(bad, self.registry)

    def test_non_bytes_profile_or_inventory_refuse(self):
        for key in ('profile_raw', 'inventory_raw'):
            for value in (self.binding[key].decode('utf-8'), None, 0, [self.binding[key]]):
                with self.subTest(key=key, value=type(value).__name__):
                    bad = dict(self.binding)
                    bad[key] = value
                    with self.assertRaises(Refused):
                        adapter.prepare_job(bad, self.registry)

    def test_uppercase_or_short_hex_pins_in_binding_refuse(self):
        for key in ('request_id', 'owner_grant_sha256', 'runtime_A', 'runtime_M', 'runtime_C'):
            for value in ('A' * 64, 'a' * 63, 'a' * 65, 'g' * 64, 'a' * 32 + 'G' + 'a' * 31):
                with self.subTest(key=key, value=value[:8]):
                    bad = dict(self.binding)
                    bad[key] = value
                    with self.assertRaises(Refused):
                        adapter.prepare_job(bad, self.registry)
        self.assertEqual(self.registry.live_calls, 0)

    def test_registry_profiles_with_extra_tuple_members_refuse(self):
        selected = self.registry.row.profiles[0]
        for rows in (((*selected, 'extra'),), ((selected[0], selected[1], selected[2]),)):
            with self.subTest(rows=rows):
                self.registry.row.profiles = rows
                with self.assertRaises(Refused):
                    adapter.prepare_job(self.binding, self.registry)

    def test_successful_preparation_result_is_canonical_and_bounded(self):
        result = adapter.prepare_job(self.binding, self.registry)
        self.assertEqual(set(result), {'status', 'job', 'activation', 'admitted',
                                       'enrollment_established', 'authority_pins_verified',
                                       'usable_for_live_submission', 'queue_or_ledger_mutated',
                                       'controller_constructed'})
        self.assertEqual(result['status'], 'SOURCE_DISABLED_JOB_PROPOSAL')
        self.assertEqual(result['job'], {
            'request_id': self.binding['request_id'], 'project': 'example-project',
            'profile': 'LOCAL_QUALITY', 'mode': 'PORTABLE',
            'profile_sha256': adapter.PROFILE_SHA256,
            'owner_grant_sha256': self.binding['owner_grant_sha256'],
            'input_tuple_sha256': adapter.INPUT_TUPLE_SHA256,
            'source_inventory_sha256': adapter.INVENTORY_SHA256,
            'runtime_A': self.binding['runtime_A'], 'runtime_M': self.binding['runtime_M'],
            'runtime_C': self.binding['runtime_C']})
        self.assertLessEqual(len(encode(result, 16384)), 16384)
        self.assertEqual(digest(encode(result['job'])),
                         digest(encode(adapter.prepare_job(self.binding, self.registry)['job'])))
        self.assertEqual(self.registry.live_calls, 0)


if __name__ == '__main__':
    unittest.main()
