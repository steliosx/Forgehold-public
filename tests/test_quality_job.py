"""NOT_RUN: pure B1 model boundaries, no R10/runtime/target imports or ports.

All mock grant/runtime/registry digests are hashes of explicit MODEL_ONLY labels.
They are never retained actual authority or enrollment evidence. Local reads are
restricted to the two pinned profile/inventory data files and model report below.
"""
import copy
import json
from pathlib import Path
import unittest

from forgehold_b1.data_rules import digest, encode, Refused
from forgehold_b1 import quality_job as adapter


ROOT = Path(__file__).resolve().parents[1]


def model_digest(role):
    return digest(('R60 MODEL_ONLY, NOT authority: ' + role).encode())


class ModelProject:
    def __init__(self):
        self.project_id = 'example-project'
        self.kind = 'APPLICATION'
        self.enabled = True  # Mock premise, not a registry enrollment operation.
        self.profiles = (('LOCAL_QUALITY', 'PORTABLE', adapter.PROFILE_SHA256,
                          adapter.INVENTORY_SHA256),)


class ModelRegistry:
    def __init__(self):
        self.row = ModelProject()
        self.resource_policy_sha256 = model_digest('resource policy')
        self.owner_adoption_sha256 = model_digest('owner adoption')
        self.enrollment_sha256 = model_digest('enrollment')
        self.project_reads = 0
        self.live_calls = 0

    def project(self, project_id):
        self.project_reads += 1
        if project_id != self.row.project_id:
            raise Refused('model project missing')
        return self.row

    def sha256(self):
        return digest(encode({'model': 'MODEL_ONLY registry, never adopted',
            'kind': self.row.kind, 'enabled': self.row.enabled,
            'profiles': self.row.profiles,
            'resource': self.resource_policy_sha256,
            'adoption': self.owner_adoption_sha256,
            'enrollment': self.enrollment_sha256}))

    def require_profile(self, *args):
        raise AssertionError('adapter must not claim protected enrollment')

    def enqueue(self, *args):
        self.live_calls += 1
        raise AssertionError('no queue/ledger/runtime calls')


def binding(registry):
    return {'profile_raw': (ROOT/'profiles/B1.profile.DISABLED.json').read_bytes(),
        'inventory_raw': (ROOT/'profiles/B1.source-inventory.DATA.json').read_bytes(),
        'profile_sha256': adapter.PROFILE_SHA256,
        'source_inventory_sha256': adapter.INVENTORY_SHA256,
        'input_tuple_sha256': adapter.INPUT_TUPLE_SHA256,
        'request_id': model_digest('unique request'),
        'owner_grant_sha256': model_digest('owner grant'),
        'runtime_A': model_digest('runtime A'), 'runtime_M': model_digest('runtime M'),
        'runtime_C': model_digest('runtime C'),
        'registry_sha256': registry.sha256(),
        'resource_policy_sha256': registry.resource_policy_sha256,
        'owner_adoption_sha256': registry.owner_adoption_sha256,
        'enrollment_sha256': registry.enrollment_sha256}


def expected(raw):
    return {'profile_sha256': adapter.PROFILE_SHA256,
        'source_inventory_sha256': adapter.INVENTORY_SHA256,
        'input_tuple_sha256': adapter.INPUT_TUPLE_SHA256,
        'repository': adapter.REPOSITORY, 'commit': adapter.COMMIT,
        'source_sha256': adapter.SOURCE_SHA256, 'harness_sha256': adapter.HARNESS_SHA256,
        'workflow_sha256': adapter.WORKFLOW_SHA256,
        'quality_runner_sha256': adapter.RUNNER_SHA256,
        'lock_pins': adapter.lock_pins(), 'tools': adapter.tool_versions(),
        'quality_report_pin': {'bytes': len(raw), 'sha256': digest(raw)},
        'job_started_at_utc': '2026-10-10T00:00:00Z',
        'job_completed_at_utc': '2026-10-10T00:00:03Z', 'maximum_quality_seconds': 330,
        'namespace': 'PRELOOP_NATIVE_UUID',
        'native_run_id': '60000000-0000-4000-8000-000000000001',
        'check_id': 600000001}  # Explicit model subject; no actual B1 run invented.


class B1JobModelTests(unittest.TestCase):
    def setUp(self):
        self.registry = ModelRegistry()
        self.binding = binding(self.registry)

    def test_model_prepares_exact_eleven_field_disabled_job(self):
        result = adapter.prepare_job(self.binding, self.registry)
        self.assertEqual(set(result['job']), set(adapter.JOB_KEYS))
        self.assertEqual(result['job']['mode'], 'PORTABLE')
        self.assertEqual(result['job']['profile'], 'LOCAL_QUALITY')
        self.assertEqual(result['job']['source_inventory_sha256'], adapter.INVENTORY_SHA256)
        self.assertEqual(self.registry.project_reads, 2)
        self.assertEqual(self.registry.live_calls, 0)
        for name in ('activation', 'admitted', 'usable_for_live_submission',
                     'authority_pins_verified', 'enrollment_established',
                     'queue_or_ledger_mutated', 'controller_constructed'):
            self.assertIs(result[name], False)

    def test_every_missing_runtime_control_grant_pin_refuses(self):
        for key in ('runtime_A', 'runtime_M', 'runtime_C', 'owner_grant_sha256',
                    'request_id', 'registry_sha256', 'owner_adoption_sha256',
                    'enrollment_sha256', 'resource_policy_sha256'):
            with self.subTest(key=key):
                bad = dict(self.binding); bad[key] = None
                with self.assertRaises(Refused):
                    adapter.prepare_job(bad, self.registry)
        self.assertEqual(self.registry.live_calls, 0)

    def test_missing_registry_refuses(self):
        with self.assertRaises(Refused):
            adapter.prepare_job(self.binding, None)

    def test_missing_project_refuses(self):
        self.registry.row.project_id = 'unrelated'
        with self.assertRaises(Refused):
            adapter.prepare_job(self.binding, self.registry)

    def test_disabled_or_nonliteral_enabled_registry_refuses(self):
        for value in (False, None, 1, 'true'):
            with self.subTest(value=value):
                self.registry.row.enabled = value
                with self.assertRaises(Refused):
                    adapter.prepare_job(self.binding, self.registry)

    def test_qualification_project_cannot_supply_application_job(self):
        self.registry.row.kind = 'QUALIFICATION'
        with self.assertRaises(Refused):
            adapter.prepare_job(self.binding, self.registry)

    def test_conflicting_profile_mode_inventory_or_duplicate_refuses(self):
        selected = self.registry.row.profiles[0]
        for rows in ((), (('LOCAL_QUALITY', 'CHECK', *selected[2:]),),
                     (('LOCAL_QUALITY', 'PORTABLE', model_digest('other profile'), selected[3]),),
                     (('LOCAL_QUALITY', 'PORTABLE', selected[2], model_digest('other inventory')),),
                     (selected, selected), list((selected,))):
            with self.subTest(rows=rows):
                self.registry.row.profiles = rows
                with self.assertRaises(Refused):
                    adapter.prepare_job(self.binding, self.registry)

    def test_each_independent_registry_control_pin_conflict_refuses(self):
        for key in ('registry_sha256', 'resource_policy_sha256',
                    'owner_adoption_sha256', 'enrollment_sha256'):
            with self.subTest(key=key):
                bad = dict(self.binding); bad[key] = model_digest('wrong ' + key)
                with self.assertRaises(Refused):
                    adapter.prepare_job(bad, self.registry)

    def test_changed_profile_activation_or_candidate_refuses(self):
        for field, value in (('activation', True), ('activation', 0)):
            with self.subTest(field=field, value=value):
                row = json.loads(self.binding['profile_raw']); row['profile'][field] = value
                raw = encode(row, 32768); bad = dict(self.binding, profile_raw=raw, profile_sha256=digest(raw))
                with self.assertRaises(Refused):
                    adapter.prepare_job(bad, self.registry)
        row = json.loads(self.binding['profile_raw']); row['source']['commit'] = '3631d2a8fdc28b6a0002b59d22dc6076be1a1276'
        raw = encode(row, 32768)
        with self.assertRaises(Refused):
            adapter.prepare_job(dict(self.binding, profile_raw=raw, profile_sha256=digest(raw)), self.registry)

    def test_changed_inventory_or_input_tuple_refuses(self):
        for key in ('source_inventory_sha256', 'input_tuple_sha256'):
            with self.subTest(key=key):
                bad = dict(self.binding); bad[key] = model_digest('wrong ' + key)
                with self.assertRaises(Refused):
                    adapter.prepare_job(bad, self.registry)

    def test_registry_mutation_during_read_refuses_without_dispatch(self):
        class Changed(ModelRegistry):
            def project(self, name):
                row = super().project(name)
                if self.project_reads == 2:
                    row.enabled = False
                return row
        registry = Changed()
        with self.assertRaises(Refused):
            adapter.prepare_job(binding(registry), registry)
        self.assertEqual(registry.live_calls, 0)

    def test_unknown_extra_binding_field_refuses(self):
        with self.assertRaises(Refused):
            adapter.prepare_job(dict(self.binding, dispatch=True), self.registry)

    def test_all_live_submission_and_publication_refuse_without_port_calls(self):
        prepared = adapter.prepare_job(self.binding, self.registry)
        for function in (adapter.dispatch, adapter.publish_result):
            with self.assertRaises(Refused):
                function(prepared, self.registry)
        self.assertEqual(self.registry.live_calls, 0)


class B1QualityModelTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT/'fixtures/quality-run.MODEL_ONLY.json').read_bytes()
        self.report = json.loads(self.raw)
        self.expected = expected(self.raw)

    def refuses_changed_report(self, row):
        raw = encode(row, 65536)
        with self.assertRaises(Refused):
            adapter.interpret_quality(raw, expected(raw))

    def test_exact_four_checks_pass_only_data_interpretation(self):
        result = adapter.interpret_quality(self.raw, self.expected)
        self.assertEqual(result['quality'], 'PASS')
        self.assertEqual(result['checks'], list(adapter.CHECKS))
        for name in ('subject_authentication_established', 'external_ports_Evidence_created',
                     'activation', 'admitted', 'cleanup_verified', 'live_custody_established',
                     'retention_established', 'slot_disposition_established',
                     'ordinary_actions_bundle_established', 'release_qualified'):
            self.assertIs(result[name], False)

    def test_bool_float_nonzero_or_string_exit_refuses_each_check(self):
        for index in range(4):
            for value in (False, True, 0.0, 1, -1, '0', None):
                with self.subTest(index=index, value=value):
                    row = copy.deepcopy(self.report); row['checks'][index]['exit_code'] = value
                    self.refuses_changed_report(row)

    def test_missing_extra_duplicate_or_reordered_checks_refuse(self):
        checks = self.report['checks']
        for variant in (checks[:3], checks+[checks[0]], checks[:3]+[checks[0]], list(reversed(checks))):
            with self.subTest(variant=variant):
                self.refuses_changed_report(dict(self.report, checks=variant))

    def test_A7_three_checks_older_source_and_subject_refuse(self):
        row = copy.deepcopy(self.report); row['checks'].pop(1)
        self.refuses_changed_report(row)
        row = copy.deepcopy(self.report); row['code_digests']['source'] = model_digest('A7 older source')
        self.refuses_changed_report(row)
        for key, value in (('native_run_id', '60000000-0000-4000-8000-000000000099'),
                           ('check_id', 600000099),
                           ('commit', '3631d2a8fdc28b6a0002b59d22dc6076be1a1276')):
            with self.subTest(key=key):
                bad = dict(self.expected); bad[key] = value
                with self.assertRaises(Refused):
                    adapter.interpret_quality(self.raw, bad)

    def test_every_source_harness_workflow_runner_profile_inventory_tuple_conflict_refuses(self):
        for key in ('source_sha256', 'harness_sha256', 'workflow_sha256',
                    'quality_runner_sha256', 'profile_sha256', 'source_inventory_sha256',
                    'input_tuple_sha256'):
            with self.subTest(key=key):
                bad = dict(self.expected); bad[key] = model_digest('wrong ' + key)
                with self.assertRaises(Refused):
                    adapter.interpret_quality(self.raw, bad)

    def test_lock_and_reported_expected_tool_conflicts_refuse(self):
        for name in adapter.lock_pins():
            bad = copy.deepcopy(self.expected); bad['lock_pins'][name]['sha256'] = model_digest('wrong lock')
            with self.assertRaises(Refused):
                adapter.interpret_quality(self.raw, bad)
        for name in adapter.tool_versions():
            row = copy.deepcopy(self.report); row['tools'][name] = '0.0'
            self.refuses_changed_report(row)
            bad = copy.deepcopy(self.expected); bad['tools'][name] = '0.0'
            with self.assertRaises(Refused):
                adapter.interpret_quality(self.raw, bad)

    def test_failed_running_skipped_timeout_and_tree_unknown_refuse(self):
        for state in ('FAIL', 'RUNNING', 'SKIP', 'UNKNOWN'):
            self.refuses_changed_report(dict(self.report, status=state))
        for value in (False, 1, None, 'true'):
            self.refuses_changed_report(dict(self.report, tree_unchanged=value))
        row = copy.deepcopy(self.report); row['checks'][1].update(status='FAIL', exit_code=-9)
        self.refuses_changed_report(row)
        self.refuses_changed_report(dict(self.report, reason='TimeoutExpired'))

    def test_stale_reversed_future_outside_window_and_late_intervals_refuse(self):
        for start, end in (('2026-10-09T00:00:00Z', '2026-10-09T00:00:02Z'),
                           ('2026-10-10T00:00:02Z', '2026-10-10T00:00:01Z'),
                           ('2026-10-11T00:00:01Z', '2026-10-11T00:00:02Z')):
            self.refuses_changed_report(dict(self.report, started_at_utc=start, finished_at_utc=end))
        bad = dict(self.expected, job_completed_at_utc='2026-10-10T00:06:00Z')
        with self.assertRaises(Refused):
            adapter.interpret_quality(self.raw, bad)

    def test_untrusted_overprecise_or_offset_timestamps_refuse(self):
        for value in ('2026-10-10T00:00:01.000000001+00:00',
                      '2026-10-10T00:00:01+00:00.1', '2026-10-10T00:00:01+01:00',
                      '2026-10-10T00:00:01', '2026-02-30T00:00:01Z'):
            self.refuses_changed_report(dict(self.report, started_at_utc=value))

    def test_unknown_truncated_changed_pin_and_oversized_report_refuse(self):
        for raw in (self.raw[:-1], self.raw+b' ', b'', b'x'*65537):
            with self.subTest(length=len(raw)):
                with self.assertRaises(Refused):
                    adapter.interpret_quality(raw, self.expected)
        with self.assertRaises(Refused):
            adapter.interpret_quality(self.raw, dict(self.expected, quality_report_pin={'bytes':len(self.raw), 'sha256':model_digest('wrong bytes')}))

    def test_duplicate_json_and_extra_missing_report_fields_refuse(self):
        raw = self.raw.replace(b'"status":"PASS"', b'"status":"PASS","status":"PASS"', 1)
        with self.assertRaises(Refused):
            adapter.interpret_quality(raw, expected(raw))
        self.refuses_changed_report(dict(self.report, cleanup_verified=True))
        row = dict(self.report); del row['tools']; self.refuses_changed_report(row)

    def test_native_UUID_and_numeric_check_ID_types_never_conflated(self):
        for key, value in (('namespace', 'GITHUB_ACTIONS'), ('native_run_id', '600000001'),
                           ('native_run_id', '00000000-0000-0000-0000-000000000000'),
                           ('check_id', True), ('check_id', 600000001.0), ('check_id', '600000001')):
            with self.subTest(key=key):
                bad = dict(self.expected); bad[key] = value
                with self.assertRaises(Refused):
                    adapter.interpret_quality(self.raw, bad)

    def test_missing_independent_binding_or_report_cannot_issue_success(self):
        for key in adapter.EXPECTED_KEYS:
            with self.subTest(key=key):
                bad = dict(self.expected); del bad[key]
                with self.assertRaises(Refused):
                    adapter.interpret_quality(self.raw, bad)

    def test_quality_PASS_cannot_dispatch_cleanup_release_or_publish(self):
        result = adapter.interpret_quality(self.raw, self.expected)
        for function in (adapter.dispatch, adapter.publish_result):
            with self.assertRaises(Refused):
                function(result)


if __name__ == '__main__':
    unittest.main()
