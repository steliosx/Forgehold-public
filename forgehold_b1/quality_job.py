"""Fixed B1 data boundaries. No runtime, ledger, launch or authority imports.

The caller independently selects report provenance and supplies a read-only
registry interface. Shape/digest checks here authenticate neither that caller
nor any issuer. Even a successful model proposal cannot be submitted live.
"""
from datetime import datetime, timezone
import re

from .data_rules import decode, digest, encode, exact, hex64, integer, require, Refused


PROJECT = 'example-project'
REPOSITORY = 'example-owner/example-project'
COMMIT = 'ef79c48fbe731dfbaa5eeaf112c482edd6005108'
SOURCE_SHA256 = '5b6d4a9984d31d458f28b21537a351dd3935351908f4f48c529c9e9348a88aaa'
HARNESS_SHA256 = '7f40a8231821ef9e6d50456048d2509d5fdfa0d914041d586f4fe4a875cabcf8'
WORKFLOW_SHA256 = '63003d3ff3a022a97a74a3f9ef7f1f038a99641c491c19000bd752b26a643ecd'
RUNNER_SHA256 = '8e51522c1ab8352713833f61a1c004cb6ff86155b98816b9a440fd9069108f2b'
PROFILE_SHA256 = '83deb8c415426e50bf5b063b7a2fa8552bbfcc69bff80df1d742e133c2620421'
INVENTORY_SHA256 = '91cc9c681090e69de98cbd01d9e39e1617690d9d7ec5f100b43ed000fd2923e9'
INPUT_TUPLE_SHA256 = '1ef9ead9cdfd32b0aa15f141c64846187f1d54fdeeaa00a67939a45cdb819355'
CHECKS = ('ruff', 'ruff-infrastructure', 'mypy', 'pip-check')
REPORT_SCOPE = 'Static checks and installed dependency consistency; no service or deployment evidence'
JOB_KEYS = ('request_id', 'project', 'profile', 'mode', 'profile_sha256',
            'owner_grant_sha256', 'input_tuple_sha256', 'source_inventory_sha256',
            'runtime_A', 'runtime_M', 'runtime_C')
BINDING_KEYS = ('profile_raw', 'inventory_raw', 'profile_sha256',
                'source_inventory_sha256', 'input_tuple_sha256', 'request_id',
                'owner_grant_sha256', 'runtime_A', 'runtime_M', 'runtime_C',
                'registry_sha256', 'resource_policy_sha256',
                'owner_adoption_sha256', 'enrollment_sha256')
EXPECTED_KEYS = ('profile_sha256', 'source_inventory_sha256', 'input_tuple_sha256',
                 'repository', 'commit', 'source_sha256', 'harness_sha256',
                 'workflow_sha256', 'quality_runner_sha256', 'lock_pins', 'tools',
                 'quality_report_pin', 'job_started_at_utc', 'job_completed_at_utc',
                 'maximum_quality_seconds', 'namespace', 'native_run_id', 'check_id')


def tool_versions():
    return {'ruff': '0.16.7', 'mypy': '2.3.1', 'hypothesis': '6.168.0'}


def lock_pins():
    return {'requirements.lock': {'bytes': 43, 'sha256': '22626211592e88fc43d9180f2983f5834b4fc5f52c3b3a5aca2eca292d8ea15c'}, 'requirements-quality.lock': {'bytes': 43, 'sha256': 'fc32c2495225819d0b6ba908c6792ecff76ceeccd42f13fb7d392dfebf8da0a4'}}


def utc_time(value):
    # Refuse unsupported precision/offsets before datetime can truncate them.
    require(type(value) is str and re.fullmatch(
        r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
        r'(?:\.[0-9]{1,6})?(?:Z|\+00:00)', value), 'bounded actual UTC timestamp')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Refused('invalid UTC timestamp') from exc
    require(result.tzinfo == timezone.utc, 'UTC correspondence')
    return result


def _pin(row):
    exact(row, ('bytes', 'sha256'))
    integer(row['bytes'], 1, 65536)
    hex64(row['sha256'])
    return row


def _profile_and_inventory(binding):
    profile_raw = binding['profile_raw']
    inventory_raw = binding['inventory_raw']
    require(type(profile_raw) is bytes and 0 < len(profile_raw) <= 32768
            and digest(profile_raw) == binding['profile_sha256'] == PROFILE_SHA256,
            'exact independently selected disabled B1 profile')
    require(type(inventory_raw) is bytes and 0 < len(inventory_raw) <= 65536
            and digest(inventory_raw) == binding['source_inventory_sha256'] == INVENTORY_SHA256,
            'exact candidate inventory, including .github and dependency locks')
    profile = decode(profile_raw, 32768, 8192)
    inventory = decode(inventory_raw, 65536, 16384)
    require(encode(profile, 32768) == profile_raw
            and encode(inventory, 65536) == inventory_raw, 'canonical fixed data')
    require(profile['profile'] == {'name': 'LOCAL_QUALITY', 'mode': 'PORTABLE',
            'adapter': 'B1_QUALITY_SOURCE_ONLY', 'activation': False,
            'execution': False, 'enrollment': False}, 'literal disabled profile')
    require(profile['source']['commit'] == inventory['commit'] == COMMIT
            and inventory['github_and_dependency_locks_in_harness'] is True,
            'B1 source scope')
    require(binding['input_tuple_sha256'] == INPUT_TUPLE_SHA256,
            'independent fixed candidate input tuple')


def _registry_snapshot(registry):
    require(registry is not None, 'read-only registry MISSING')
    project = registry.project(PROJECT)
    require(project.project_id == PROJECT and project.kind == 'APPLICATION'
            and project.enabled is True, 'missing/disabled application registry membership')
    profiles = project.profiles
    require(type(profiles) is tuple and 0 < len(profiles) <= 8, 'bounded immutable profiles')
    for item in profiles:
        require(type(item) is tuple and len(item) == 4, 'existing profile row shape')
        require(type(item[0]) is str and type(item[1]) is str, 'profile names')
        hex64(item[2]); hex64(item[3])
    require(len(set(item[:3] for item in profiles)) == len(profiles), 'duplicate profile key')
    selected = ('LOCAL_QUALITY', 'PORTABLE', PROFILE_SHA256, INVENTORY_SHA256)
    require(sum(item == selected for item in profiles) == 1, 'conflicting profile/inventory binding')
    result = {'registry_sha256': hex64(registry.sha256()),
              'resource_policy_sha256': hex64(registry.resource_policy_sha256),
              'owner_adoption_sha256': hex64(registry.owner_adoption_sha256),
              'enrollment_sha256': hex64(registry.enrollment_sha256),
              'project_id': project.project_id, 'kind': project.kind,
              'enabled': project.enabled, 'profiles': profiles}
    encode(result, 16384)
    return result


def prepare_job(explicit_B1_binding, existing_registry):
    """Produce a disabled proposal using the existing eleven-field job shape.

    Missing runtime/grant/adoption/enrollment/resource pins refuse formation;
    supplied 64hex values are compared as DATA, never verified Authorities.
    No Policy, require_profile, Controller, queue or ledger is constructed.
    """
    binding = exact(explicit_B1_binding, BINDING_KEYS)
    _profile_and_inventory(binding)
    for key in BINDING_KEYS:
        if key not in ('profile_raw', 'inventory_raw'):
            hex64(binding[key])
    first = _registry_snapshot(existing_registry)
    for key in ('registry_sha256', 'resource_policy_sha256',
                'owner_adoption_sha256', 'enrollment_sha256'):
        require(first[key] == binding[key], 'independent registry/control pin conflict: ' + key)
    job = {'request_id': binding['request_id'], 'project': PROJECT,
           'profile': 'LOCAL_QUALITY', 'mode': 'PORTABLE',
           'profile_sha256': PROFILE_SHA256,
           'owner_grant_sha256': binding['owner_grant_sha256'],
           'input_tuple_sha256': INPUT_TUPLE_SHA256,
           'source_inventory_sha256': INVENTORY_SHA256,
           'runtime_A': binding['runtime_A'], 'runtime_M': binding['runtime_M'],
           'runtime_C': binding['runtime_C']}
    exact(job, JOB_KEYS)
    encode(job, 16384)
    require(_registry_snapshot(existing_registry) == first, 'registry metadata changed during preparation')
    return {'status': 'SOURCE_DISABLED_JOB_PROPOSAL', 'job': job,
            'activation': False, 'admitted': False, 'enrollment_established': False,
            'authority_pins_verified': False, 'usable_for_live_submission': False,
            'queue_or_ledger_mutated': False, 'controller_constructed': False}


def _expected(expected):
    exact(expected, EXPECTED_KEYS)
    require(expected['profile_sha256'] == PROFILE_SHA256
            and expected['source_inventory_sha256'] == INVENTORY_SHA256
            and expected['input_tuple_sha256'] == INPUT_TUPLE_SHA256,
            'independently selected B1 profile/inventory/input tuple')
    require(expected['repository'] == REPOSITORY and expected['commit'] == COMMIT
            and expected['source_sha256'] == SOURCE_SHA256
            and expected['harness_sha256'] == HARNESS_SHA256
            and expected['workflow_sha256'] == WORKFLOW_SHA256
            and expected['quality_runner_sha256'] == RUNNER_SHA256,
            'independent exact B1 source/harness/workflow/runner bindings')
    exact(expected['lock_pins'], lock_pins())
    for value in expected['lock_pins'].values():
        _pin(value)
    require(expected['lock_pins'] == lock_pins() and expected['tools'] == tool_versions(),
            'fixed B1 dependency locks/tool versions')
    _pin(expected['quality_report_pin'])
    require(expected['namespace'] == 'PRELOOP_NATIVE_UUID'
            and type(expected['native_run_id']) is str and re.fullmatch(
                r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', expected['native_run_id'])
            and expected['native_run_id'] not in (
                '00000000-0000-0000-0000-000000000000',
                '60000000-0000-4000-8000-000000000099'), 'fresh selected native subject, never A7/numeric Actions run')
    integer(expected['check_id'], 1, 2**63-1)
    require(expected['check_id'] != 600000099, 'A7 check cannot be rebound to B1')
    integer(expected['maximum_quality_seconds'], 1, 330)
    start = utc_time(expected['job_started_at_utc'])
    end = utc_time(expected['job_completed_at_utc'])
    require(start <= end and (end-start).total_seconds() <= expected['maximum_quality_seconds'],
            'independently selected bounded actual job interval')
    return start, end


def interpret_quality(exact_quality_run_bytes, independent_expected_binding):
    """Interpret exact selected report bytes, never live Evidence or cleanup.

    B1 report omits commit/workflow/locks/native subject: these must come from
    independent selection. This pure parser cannot authenticate that selection
    or prove tool binary identity, clocks, custody, freshness or run-subject
    issuance. No UUID/check ID is derived from the report or manufactured here.
    Failure/truncation/pin conflict refuses and never rewrites the source report.
    """
    expected = independent_expected_binding
    start, end = _expected(expected)
    raw = exact_quality_run_bytes
    require(type(raw) is bytes and 0 < len(raw) <= 65536, 'quality report byte bound')
    require(len(raw) == expected['quality_report_pin']['bytes']
            and digest(raw) == expected['quality_report_pin']['sha256'],
            'independent exact quality report pin')
    report = decode(raw, 65536, 8192)
    exact(report, ('status', 'checks', 'code_digests', 'started_at_utc',
                  'finished_at_utc', 'scope', 'tools', 'tree_unchanged'))
    require(report['status'] == 'PASS' and report['tree_unchanged'] is True
            and report['scope'] == REPORT_SCOPE, 'quality PASS and literal tree stability required')
    exact(report['code_digests'], ('source', 'harness'))
    require(report['code_digests'] == {'source': SOURCE_SHA256, 'harness': HARNESS_SHA256},
            'fresh selected B1 source/harness, not A7/older-source records')
    require(report['tools'] == expected['tools'] == tool_versions(), 'actual reported pinned tools')
    checks = report['checks']
    require(type(checks) is list and len(checks) == 4, 'exact four ordered B1 checks')
    for name, check in zip(CHECKS, checks):
        exact(check, ('name', 'status', 'exit_code'))
        require(check['name'] == name and check['status'] == 'PASS'
                and type(check['exit_code']) is int and check['exit_code'] == 0,
                'literal-int exit0/PASS for exact ordered check: ' + name)
    report_start = utc_time(report['started_at_utc'])
    report_end = utc_time(report['finished_at_utc'])
    require(start <= report_start <= report_end <= end, 'actual UTC report interval ordering')
    return {'quality': 'PASS', 'evidence_level': 'SELECTED_B1_REPORT_BYTES_ONLY',
            'commit': COMMIT, 'profile_sha256': PROFILE_SHA256,
            'source_inventory_sha256': INVENTORY_SHA256,
            'input_tuple_sha256': INPUT_TUPLE_SHA256,
            'quality_report_sha256': digest(raw), 'checks': list(CHECKS),
            'selected_native_run_id': expected['native_run_id'],
            'selected_numeric_check_id': expected['check_id'],
            'subject_authentication_established': False,
            'external_ports_Evidence_created': False, 'activation': False,
            'admitted': False, 'cleanup_verified': False, 'live_custody_established': False,
            'retention_established': False, 'slot_disposition_established': False,
            'ordinary_actions_bundle_established': False, 'release_qualified': False}


def dispatch(*args, **kwargs):
    raise Refused('SOURCE_DISABLED: executor/requester/grant/guardian/clock/admission MISSING; no enqueue/dispatch')


def publish_result(*args, **kwargs):
    raise Refused('SOURCE_DISABLED: authenticated result publisher/custody/disposition MISSING')
