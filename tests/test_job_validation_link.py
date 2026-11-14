"""NOT_RUN: R61 link definitions against contract v4; pure models, no cp_s1/runtime/target import.

The model validator below RESTATES the R10 validate_job LOCAL_QUALITY path (controller_policy.py
:122-144) against a model registry whose require_profile/source_inventory restate
project_registry.py :47-57. It is MODEL_ONLY: nothing here is the protected function, an enrolled
registry or any authority. Read-count devices (flipping on the Nth project() read) are the same
technique as the original test_registry_mutation_during_read_refuses_without_dispatch.
"""
import unittest

from forgehold_b1.data_rules import digest, encode, Refused
from forgehold_b1 import quality_job as adapter
from forgehold_b1 import job_validation_link as link
from tests.test_quality_job import ModelRegistry, binding, model_digest


PORTABLE_MODES = ('CHECK', 'PORTABLE', 'FAULT_STARTUP_STALL', 'FAULT_DESCENDANT_HANG',
                  'FAULT_TRUNCATED_OUTPUT', 'FAULT_OUTPUT_QUOTA')  # controller_policy.py :11-13


class ModelRegistryR10(ModelRegistry):
    """Adds R10-shaped require_profile/source_inventory (:47-57) and a sha256() call counter."""

    def __init__(self):
        super().__init__()
        self.sha256_calls = 0

    def sha256(self):
        self.sha256_calls += 1
        return super().sha256()

    def require_profile(self, project_id, profile, mode, profile_sha256):
        p = self.project(project_id)
        if not (p.enabled is True and any(v[:3] == (profile, mode, profile_sha256) for v in p.profiles)):
            raise Refused('project/profile not enabled and enrolled')
        return p

    def source_inventory(self, project_id, profile, mode, profile_sha256):
        p = self.require_profile(project_id, profile, mode, profile_sha256)
        found = tuple(v[3] for v in p.profiles if v[:3] == (profile, mode, profile_sha256))
        if len(found) != 1:
            raise Refused('unique source inventory binding')
        return found[0]


class Flipping(ModelRegistryR10):
    """Sets enabled=False on exactly the flip_at-th project() read (read-count device)."""
    flip_at = None  # set by the test after the proposal has been prepared

    def project(self, name):
        row = super().project(name)
        if self.project_reads == self.flip_at:
            row.enabled = False
        return row


class ModelContext:
    def __init__(self, registry, resource_profile='PRODUCTION_PORTABLE'):
        self.project_registry = registry
        self.resource_profile = resource_profile


def model_validate_job(row, policy):
    """MODEL_ONLY restatement of controller_policy.validate_job :122-144 (LOCAL_QUALITY path)."""
    if not (type(row) is dict and set(row) == set(adapter.JOB_KEYS)):
        raise Refused('job schema')
    project = policy.project_registry.require_profile(row['project'], row['profile'],
                                                      row['mode'], row['profile_sha256'])
    if not (row['profile'] == 'LOCAL_QUALITY' and row['mode'] in PORTABLE_MODES):
        raise Refused('fixed profile')
    expected = policy.project_registry.source_inventory(row['project'], row['profile'],
                                                        row['mode'], row['profile_sha256'])
    if row['source_inventory_sha256'] != expected:
        raise Refused('fixed source scope')
    if policy.resource_profile == 'LIFECYCLE_ONE_CASE_V1' and row['profile'] != 'METADATA':
        raise Refused('first-case profile cannot launch application CI')
    return dict(row)


class Counting:
    """Wraps a validator to count calls and remember the argument object it received."""

    def __init__(self, function):
        self.function = function
        self.calls = 0
        self.argument = None

    def __call__(self, row, context):
        self.calls += 1
        self.argument = row
        return self.function(row, context)


def proposal_bytes(registry):
    return encode(adapter.prepare_job(binding(registry), registry), 16384)


def pins_for(raw):
    return {'proposal_sha256': digest(raw), 'profile_sha256': adapter.PROFILE_SHA256,
            'source_inventory_sha256': adapter.INVENTORY_SHA256,
            'input_tuple_sha256': adapter.INPUT_TUPLE_SHA256,
            'validator_reference': {'source_sha256': model_digest('R10 validate_job source'),
                                    'path_label': 'cp_s1/controller_policy.py'}}


class LinkSuccessModelTests(unittest.TestCase):
    def setUp(self):
        self.registry = ModelRegistryR10()
        self.raw = proposal_bytes(self.registry)
        self.pins = pins_for(self.raw)
        self.expected_job = adapter.prepare_job(binding(self.registry), self.registry)['job']
        self.context = ModelContext(self.registry)
        self.validator = Counting(model_validate_job)
        # setUp itself read the registry (binding(), prepare_job); count only the link's deltas.
        self.p0, self.s0 = self.registry.project_reads, self.registry.sha256_calls

    def test_group1_link_only_result_counts_and_accounting(self):
        result = link.link_job(self.raw, self.pins, self.context, self.validator)
        self.assertEqual(result['status'], 'SOURCE_JOB_VALIDATION_LINK_ONLY')
        self.assertEqual(result['flag_scope'], 'BRIDGE_OWN_ACTIONS_ONLY')
        self.assertEqual(set(result), {'status', 'job', 'proposal_sha256', 'snapshot_sha256',
                                       'validator_reference', 'resource_profile_observed',
                                       'serialized_bytes_before_result', 'flag_scope',
                                       *link.RESULT_FLAGS})
        for flag in link.RESULT_FLAGS:
            self.assertIs(result[flag], False)
        self.assertEqual(result['job'], self.expected_job)
        self.assertEqual(self.validator.calls, 1)
        # attempted project() reads: 2 bridge-owned + 2 validator-owned (contract 7.2)
        self.assertEqual(self.registry.project_reads - self.p0, 4)
        self.assertEqual(self.registry.sha256_calls - self.s0, 2)
        self.assertEqual(self.registry.live_calls, 0)
        self.assertEqual(result['resource_profile_observed'], 'PRODUCTION_PORTABLE')
        self.assertEqual(result['proposal_sha256'], digest(self.raw))

    def test_group1_pre_result_sum_equals_independent_component_sum(self):
        registry = ModelRegistryR10(); raw = proposal_bytes(registry); pins = pins_for(raw)
        context = ModelContext(registry)
        result = link.link_job(raw, pins, context, model_validate_job)
        # Test-local encoding of the contract section 3 field set (independent of link._observe).
        row = registry.row
        observation = encode({'registry_sha256': registry.sha256(),
                              'resource_policy_sha256': registry.resource_policy_sha256,
                              'owner_adoption_sha256': registry.owner_adoption_sha256,
                              'enrollment_sha256': registry.enrollment_sha256,
                              'project_id': row.project_id, 'kind': row.kind,
                              'enabled': row.enabled, 'profiles': row.profiles,
                              'resource_profile': 'PRODUCTION_PORTABLE'}, 16384)
        independent = (len(raw) + len(encode(pins, 16384))
                       + len(encode(result['job'], 16384)) + 2 * len(observation))
        self.assertEqual(result['serialized_bytes_before_result'], independent)
        self.assertLessEqual(independent, 65536 - 16384)
        self.assertEqual(result['snapshot_sha256'], digest(observation))

    def test_group1_bridge_never_calls_require_profile_or_enqueue_itself(self):
        plain = ModelRegistry()  # its require_profile/enqueue raise AssertionError
        raw = proposal_bytes(plain); context = ModelContext(plain)
        result = link.link_job(raw, pins_for(raw), context, lambda row, ctx: dict(row))
        self.assertEqual(result['status'], 'SOURCE_JOB_VALIDATION_LINK_ONLY')
        self.assertEqual(plain.live_calls, 0)

    def test_group1_output_job_is_a_fresh_copy_not_argument_or_return(self):
        result = link.link_job(self.raw, self.pins, self.context, self.validator)
        self.assertIsNot(result['job'], self.validator.argument)
        result['job']['runtime_A'] = 'x'
        self.assertNotEqual(self.validator.argument['runtime_A'], 'x')


class LinkRefusalBeforeCallbackTests(unittest.TestCase):
    def setUp(self):
        self.registry = ModelRegistryR10()
        self.raw = proposal_bytes(self.registry)
        self.pins = pins_for(self.raw)
        self.context = ModelContext(self.registry)
        self.validator = Counting(model_validate_job)
        self.reads, self.s0 = self.registry.project_reads, self.registry.sha256_calls

    def refuses(self, raw=None, pins=None, context='same', validator='same'):
        with self.assertRaises(Refused):
            link.link_job(self.raw if raw is None else raw, self.pins if pins is None else pins,
                          self.context if context == 'same' else context,
                          self.validator if validator == 'same' else validator)
        self.assertEqual(self.validator.calls, 0)

    def refuses_with_reads(self, expected_project_reads, **kw):
        """Observation-1 failure: the attempted project() reads are counted, no observation completes."""
        start = self.registry.project_reads
        self.refuses(**kw)
        self.assertEqual(self.registry.project_reads - start, expected_project_reads)

    def test_group2_missing_context_or_non_callable_refuse_with_zero_registry_reads(self):
        self.refuses(context=None)
        for bad in (None, 'validate_job', 7):
            with self.subTest(bad=bad):
                self.refuses(validator=bad)
        self.assertEqual(self.registry.project_reads, self.reads)
        self.assertEqual(self.registry.sha256_calls, self.s0)

    def test_group3_proposal_bytes_faults_refuse(self):
        for raw in (self.raw[:-1], self.raw + b' ', b'', b'x' * 16385, self.raw.decode(), None):
            with self.subTest(kind=type(raw).__name__, length=len(raw) if raw is not None else -1):
                with self.assertRaises(Refused):
                    link.link_job(raw, self.pins, self.context, self.validator)
        self.assertEqual(self.validator.calls, 0)

    def changed(self, mutate):
        import json
        value = json.loads(self.raw); mutate(value)
        raw = encode(value, 16384)
        return raw, pins_for(raw)

    def test_group3_proposal_schema_literal_and_type_faults_refuse(self):
        cases = [
            lambda v: v.__setitem__('status', 'source_disabled_job_proposal'),
            lambda v: v.__setitem__('extra', 1),
            lambda v: v.pop('admitted'),
            lambda v: v.__setitem__('activation', 0),
            lambda v: v.__setitem__('activation', None),
            lambda v: v.__setitem__('controller_constructed', 'False'),
            lambda v: v['job'].__setitem__('mode', 'CHECK'),
            lambda v: v['job'].__setitem__('project', 'another-project'),
            lambda v: v['job'].__setitem__('profile_sha256', model_digest('other')),
            lambda v: v['job'].__setitem__('runtime_A', model_digest('x').upper()),
            lambda v: v['job'].__setitem__('runtime_M', 1.0),
            lambda v: v['job'].__setitem__('request_id', True),
            lambda v: v['job'].__setitem__('note', 'x'),
            lambda v: v['job'].pop('runtime_C'),
        ]
        for index, mutate in enumerate(cases):
            with self.subTest(case=index):
                raw, pins = self.changed(mutate)
                self.refuses(raw=raw, pins=pins)

    def test_group3_non_canonical_or_duplicate_key_proposal_bytes_refuse(self):
        spaced = self.raw.replace(b',', b', ', 1)
        self.refuses(raw=spaced, pins=pins_for(spaced))
        duplicated = self.raw.replace(b'"admitted":false', b'"admitted":false,"admitted":false', 1)
        self.refuses(raw=duplicated, pins=pins_for(duplicated))

    def test_group3_pin_faults_refuse(self):
        for key in link.PIN_KEYS:
            with self.subTest(missing=key):
                bad = dict(self.pins); del bad[key]; self.refuses(pins=bad)
        for key in ('proposal_sha256', 'profile_sha256', 'source_inventory_sha256', 'input_tuple_sha256'):
            with self.subTest(wrong=key):
                bad = dict(self.pins); bad[key] = model_digest('wrong ' + key); self.refuses(pins=bad)
        self.refuses(pins=dict(self.pins, extra=1))
        for reference in ({'source_sha256': model_digest('v')},
                          {'source_sha256': model_digest('v'), 'path_label': ''},
                          {'source_sha256': model_digest('v'), 'path_label': 'x' * 241},
                          {'source_sha256': model_digest('v'), 'path_label': 'café'},
                          {'source_sha256': model_digest('v'), 'path_label': 'p', 'extra': 1},
                          {'source_sha256': 'short', 'path_label': 'p'}):
            with self.subTest(reference=reference):
                self.refuses(pins=dict(self.pins, validator_reference=reference))

    def test_group6_and_9_snapshot_field_and_bound_faults_refuse_before_callback(self):
        selected = self.registry.row.profiles[0]
        for rows in ((selected, ('x' * 65, 'PORTABLE', model_digest('a'), model_digest('b'))),
                     (selected, ('LOCAL_QUALITY', 'café', model_digest('a'), model_digest('b'))),
                     (selected, ('', 'CHECK', model_digest('a'), model_digest('b'))),
                     tuple([selected] + [('p%d' % i, 'CHECK', model_digest('a%d' % i), model_digest('b')) for i in range(8)]),
                     (), (selected, selected), ((*selected, 'extra'),)):
            with self.subTest(rows=len(rows)):
                self.registry.row.profiles = rows
                self.refuses_with_reads(1)
        self.registry.row.profiles = (selected,)
        for value in (False, None, 1, 'true'):
            with self.subTest(enabled=value):
                self.registry.row.enabled = value
                self.refuses_with_reads(1)
        self.registry.row.enabled = True
        self.registry.row.kind = 'QUALIFICATION'; self.refuses_with_reads(1); self.registry.row.kind = 'APPLICATION'
        for value in ('production_portable', 'OTHER', None, 1):
            with self.subTest(resource_profile=value):
                self.refuses_with_reads(1, context=ModelContext(self.registry, value))

        class NoRegistry:
            resource_profile = 'PRODUCTION_PORTABLE'
        self.refuses_with_reads(0, context=NoRegistry())       # missing registry: no read possible
        self.registry.resource_policy_sha256 = None
        self.refuses_with_reads(1)
        # every case above: one attempted project() read, zero completed observations, zero calls
        self.assertEqual(self.validator.calls, 0)

    def test_group7b_isolated_accounting_predicate(self):
        self.assertEqual(link._account(65536 - 16384, 16384), 65536 - 16384)
        self.assertEqual(link._account(0, 1), 0)
        for before, bound in ((65536 - 16384 + 1, 16384), (65536, 1), (-1, 16384), (0, 0),
                              (0, 16385), (True, 16384), (0, 16384.0), (None, 16384)):
            with self.subTest(before=before, bound=bound):
                with self.assertRaises(Refused):
                    link._account(before, bound)


class LinkCallbackOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.registry = ModelRegistryR10()
        self.raw = proposal_bytes(self.registry)
        self.pins = pins_for(self.raw)
        self.context = ModelContext(self.registry)
        self.reads, self.s0 = self.registry.project_reads, self.registry.sha256_calls

    def attempted_reads(self):
        return self.registry.project_reads - self.reads

    def sha256_delta(self):
        return self.registry.sha256_calls - self.s0

    def test_group4_returned_job_changed_extra_missing_or_type_changed_refuses_after_one_call(self):
        def returning(change):
            def validator(row, context):
                out = dict(row); change(out); return out
            return Counting(validator)
        for change in (lambda o: o.__setitem__('runtime_A', model_digest('other')),
                       lambda o: o.__setitem__('note', 'x'),
                       lambda o: o.pop('runtime_C'),
                       lambda o: o.__setitem__('request_id', o['request_id'].encode()),
                       lambda o: o.__setitem__('mode', 'CHECK')):
            with self.subTest():
                self.registry = ModelRegistryR10(); self.context = ModelContext(self.registry)
                raw = proposal_bytes(self.registry)
                self.reads, self.s0 = self.registry.project_reads, self.registry.sha256_calls
                validator = returning(change)
                with self.assertRaises(Refused):
                    link.link_job(raw, pins_for(raw), self.context, validator)
                self.assertEqual(validator.calls, 1)
                self.assertEqual(self.attempted_reads(), 1)       # observation 1 only; no observation 2
                self.assertEqual(self.sha256_delta(), 1)
        for bad in (None, ['x'], 'job', 7):
            with self.subTest(returned=type(bad).__name__):
                self.registry = ModelRegistryR10(); self.context = ModelContext(self.registry)
                raw = proposal_bytes(self.registry)
                self.reads, self.s0 = self.registry.project_reads, self.registry.sha256_calls
                validator = Counting(lambda row, context, bad=bad: bad)
                with self.assertRaises(Refused):
                    link.link_job(raw, pins_for(raw), self.context, validator)
                self.assertEqual(validator.calls, 1)
                self.assertEqual(self.attempted_reads(), 1)
                self.assertEqual(self.sha256_delta(), 1)

    def test_group4prime_in_place_mutation_returning_same_object_refuses(self):
        def validator(row, context):
            row['runtime_A'] = model_digest('mutated in place'); return row
        counting = Counting(validator)
        with self.assertRaises(Refused):
            link.link_job(self.raw, self.pins, self.context, counting)
        self.assertEqual(counting.calls, 1)
        self.assertEqual(self.attempted_reads(), 1)

    def test_group4doubleprime_in_place_mutation_returning_separate_equal_copy_refuses(self):
        def validator(row, context):
            clean = dict(row); row['runtime_A'] = model_digest('mutated argument'); return clean
        counting = Counting(validator)
        with self.assertRaises(Refused):
            link.link_job(self.raw, self.pins, self.context, counting)
        self.assertEqual(counting.calls, 1)
        self.assertEqual(self.attempted_reads(), 1)

    def test_group4tripleprime_enabled_flip_between_observations_refuses(self):
        registry = Flipping(); raw = proposal_bytes(registry); context = ModelContext(registry)
        registry.flip_at = registry.project_reads + 4      # the 4th read of the link = observation 2
        validator = Counting(model_validate_job)
        start, s0 = registry.project_reads, registry.sha256_calls
        with self.assertRaises(Refused):
            link.link_job(raw, pins_for(raw), context, validator)
        self.assertEqual(validator.calls, 1)
        self.assertEqual(registry.project_reads - start, 4)   # 2 attempts, 1 completed observation
        self.assertEqual(registry.sha256_calls - s0, 1)       # observation 2 failed before sha256()

    def test_group5_callback_exception_identity_one_call_no_second_observation(self):
        class Custom(Exception):
            pass
        for exc in (Refused('model refusal'), AttributeError('model attribute'), Custom('model')):
            with self.subTest(exc=type(exc).__name__):
                registry = ModelRegistryR10(); raw = proposal_bytes(registry)
                context = ModelContext(registry)
                start, s0 = registry.project_reads, registry.sha256_calls

                def validator(row, ctx, exc=exc):
                    raise exc
                counting = Counting(validator)
                with self.assertRaises(type(exc)) as caught:
                    link.link_job(raw, pins_for(raw), context, counting)
                self.assertIs(caught.exception, exc)
                self.assertEqual(counting.calls, 1)
                self.assertEqual(registry.project_reads - start, 1)   # 1 completed observation, 1 attempted read
                self.assertEqual(registry.sha256_calls - s0, 1)

    def test_group5_r10_shaped_refusal_in_first_require_profile_two_attempted_reads(self):
        registry = Flipping(); raw = proposal_bytes(registry); context = ModelContext(registry)
        registry.flip_at = registry.project_reads + 2      # the callback's first require_profile read
        validator = Counting(model_validate_job)
        start, s0 = registry.project_reads, registry.sha256_calls
        with self.assertRaises(Refused) as caught:
            link.link_job(raw, pins_for(raw), context, validator)
        self.assertEqual(str(caught.exception), 'project/profile not enabled and enrolled')
        self.assertEqual(validator.calls, 1)
        self.assertEqual(registry.project_reads - start, 2)   # 1 bridge + 1 validator-owned
        self.assertEqual(registry.sha256_calls - s0, 1)

    def test_group5_lifecycle_one_case_context_is_recorded_and_r10_shaped_callback_refuses(self):
        context = ModelContext(self.registry, 'LIFECYCLE_ONE_CASE_V1')
        validator = Counting(model_validate_job)
        with self.assertRaises(Refused) as caught:
            link.link_job(self.raw, self.pins, context, validator)
        self.assertEqual(str(caught.exception), 'first-case profile cannot launch application CI')
        self.assertEqual(validator.calls, 1)
        result = link.link_job(self.raw, self.pins, context, lambda row, ctx: dict(row))
        self.assertEqual(result['resource_profile_observed'], 'LIFECYCLE_ONE_CASE_V1')

    def test_group8_dispatch_publish_and_enqueue_refuse(self):
        result = link.link_job(self.raw, self.pins, self.context, model_validate_job)
        for function in (link.dispatch, link.publish_result, adapter.dispatch, adapter.publish_result):
            with self.assertRaises(Refused):
                function(result, self.context)
        with self.assertRaises(AssertionError):
            self.registry.enqueue(result)
        self.assertEqual(self.registry.live_calls, 1)  # the mock counted our direct call only


def copy_callback(row, context):
    return dict(row)   # no registry read; the simplest valid validator shape


def local_observation(registry, project_id, kind, enabled, profiles, resource_profile='PRODUCTION_PORTABLE'):
    """Test-local encoding of the contract section 3 fields from CHECKED values."""
    return encode({'registry_sha256': registry.sha256_value, 'resource_policy_sha256': registry.resource_policy_sha256,
                   'owner_adoption_sha256': registry.owner_adoption_sha256,
                   'enrollment_sha256': registry.enrollment_sha256, 'project_id': project_id, 'kind': kind,
                   'enabled': enabled, 'profiles': profiles, 'resource_profile': resource_profile}, 16384)


class Successor03ProviderFaultTests(unittest.TestCase):
    """definitions 1-6: capture-once encoding and bridge-owned fault normalisation."""

    def setUp(self):
        self.registry = ModelRegistryR10()
        self.raw = proposal_bytes(self.registry)
        self.pins = pins_for(self.raw)

    def test_def1_provider_mutating_row_during_sha256_cannot_change_what_is_encoded(self):
        class Mutating(ModelRegistryR10):
            def __init__(self):
                super().__init__()
                self.sha256_value = ModelRegistry.sha256(self)   # digest of the VALID state, fixed
            def project(self, name):
                row = super().project(name)
                row.kind, row.enabled = 'APPLICATION', True        # valid at every project() read
                return row
            def sha256(self):
                self.sha256_calls += 1
                self.row.kind = 'K' * 20000                        # mutation AFTER the bridge's captures
                self.row.enabled = False
                return self.sha256_value
        # The proposal is built from a plain model registry: the R60 adapter's own snapshot would
        # refuse on the Mutating one (it reads row fields after sha256(); the 20,000-char kind breaks
        # its encode bound), which is the adapter's correct behaviour and not under test here.
        registry = Mutating(); raw = proposal_bytes(ModelRegistryR10()); context = ModelContext(registry)
        checked_profiles = registry.row.profiles
        p0, s0 = registry.project_reads, registry.sha256_calls
        validator = Counting(copy_callback)
        result = link.link_job(raw, pins_for(raw), context, validator)
        self.assertEqual(result['status'], 'SOURCE_JOB_VALIDATION_LINK_ONLY')
        for flag in link.RESULT_FLAGS:
            self.assertIs(result[flag], False)
        self.assertEqual(validator.calls, 1)
        self.assertEqual((registry.project_reads - p0, registry.sha256_calls - s0), (2, 2))
        expected = local_observation(registry, 'example-project', 'APPLICATION', True, checked_profiles)
        self.assertEqual(result['snapshot_sha256'], digest(expected))   # checked locals only
        self.assertEqual(registry.row.kind, 'K' * 20000)                 # the mutation did happen
        self.assertLessEqual(result['serialized_bytes_before_result'], 65536 - 16384)

    def test_def2_fresh_rows_with_second_access_poison_are_read_once_per_field(self):
        class PoisonRow:
            def __init__(self, profiles):
                self._profiles = profiles
                self.accesses = {'project_id': 0, 'kind': 0, 'enabled': 0, 'profiles': 0}
            @property
            def project_id(self):
                self.accesses['project_id'] += 1
                return 'example-project' if self.accesses['project_id'] == 1 else 'z' * 20000
            @property
            def kind(self):
                self.accesses['kind'] += 1
                return 'APPLICATION' if self.accesses['kind'] == 1 else 17
            @property
            def enabled(self):
                self.accesses['enabled'] += 1
                return True if self.accesses['enabled'] == 1 else 1
            @property
            def profiles(self):
                self.accesses['profiles'] += 1
                return self._profiles if self.accesses['profiles'] == 1 else ()

        class FreshRows(ModelRegistryR10):
            def __init__(self):
                super().__init__()
                self.rows = []
                self.sha256_value = ModelRegistry.sha256(self)
            def project(self, name):
                self.project_reads += 1
                row = PoisonRow(self.row.profiles); self.rows.append(row); return row
            def sha256(self):
                self.sha256_calls += 1
                return self.sha256_value
        registry = FreshRows(); raw = proposal_bytes(ModelRegistryR10())   # proposal from a plain model
        context = ModelContext(registry)
        p0, s0 = registry.project_reads, registry.sha256_calls
        validator = Counting(copy_callback)
        result = link.link_job(raw, pins_for(raw), context, validator)
        self.assertEqual(result['status'], 'SOURCE_JOB_VALIDATION_LINK_ONLY')
        self.assertEqual((registry.project_reads - p0, registry.sha256_calls - s0), (2, 2))
        self.assertEqual(len(registry.rows), 2)
        for row in registry.rows:
            self.assertEqual(row.accesses, {'project_id': 1, 'kind': 1, 'enabled': 1, 'profiles': 1})
        expected = local_observation(registry, 'example-project', 'APPLICATION', True, registry.row.profiles)
        self.assertEqual(result['snapshot_sha256'], digest(expected))

    def test_def3_permissive_equality_non_string_fields_refuse_before_serialization(self):
        class Permissive:
            def __eq__(self, other):
                return True
            __hash__ = None
        for field in ('project_id', 'kind'):
            with self.subTest(field=field):
                registry = ModelRegistryR10(); raw = proposal_bytes(registry); context = ModelContext(registry)
                setattr(registry.row, field, Permissive())
                p0, s0 = registry.project_reads, registry.sha256_calls
                validator = Counting(copy_callback)
                with self.assertRaises(Refused):
                    link.link_job(raw, pins_for(raw), context, validator)
                self.assertEqual((registry.project_reads - p0, registry.sha256_calls - s0, validator.calls), (1, 0, 0))

    def test_def4_invalid_utf8_and_invalid_json_refuse_with_zero_reads_and_calls(self):
        context = ModelContext(self.registry)
        p0, s0 = self.registry.project_reads, self.registry.sha256_calls
        validator = Counting(copy_callback)
        for raw in (b'\xff', b'\xff' * 100, b'{"status":}', b'{"status": "x"', b'[1, 2', b'nul', b'{"a":1}}'):
            with self.subTest(raw=raw[:12]):
                with self.assertRaises(Refused):
                    link.link_job(raw, pins_for(raw), context, validator)
        # existing data_rules refusals are untouched: duplicate key, NaN, depth
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[' * 17 + b']' * 17):
            with self.subTest(raw=raw[:12]):
                with self.assertRaises(Refused):
                    link.link_job(raw, pins_for(raw), context, validator)
        self.assertEqual((self.registry.project_reads - p0, self.registry.sha256_calls - s0, validator.calls), (0, 0, 0))

    def test_def5_row_missing_or_none_or_wrong_typed_fields_refuse_after_one_project_read(self):
        class Row:
            pass
        base = self.registry.row
        def make(**fields):
            row = Row()
            for name in ('project_id', 'kind', 'enabled', 'profiles'):
                if name in fields:
                    if fields[name] is not Ellipsis:
                        setattr(row, name, fields[name])
                else:
                    setattr(row, name, getattr(base, name))
            return row
        # project_id variants are not listed: the model registry's own project() compares
        # row.project_id before returning (an omitted attribute would raise AttributeError inside the
        # MOCK, a wrong value its own Refused), so they would not exercise the bridge boundary.
        variants = [make(kind=...), make(profiles=...), make(enabled=...),
                    make(kind=None), make(profiles=None), make(enabled=None),
                    make(kind='application'), make(kind=b'APPLICATION'),
                    make(enabled=1), make(enabled='true'), make(profiles=list(base.profiles))]
        for index, row in enumerate(variants):
            with self.subTest(variant=index):
                registry = ModelRegistryR10(); raw = proposal_bytes(registry); context = ModelContext(registry)
                registry.row = row                       # project() still returns successfully
                p0, s0 = registry.project_reads, registry.sha256_calls
                validator = Counting(copy_callback)
                with self.assertRaises(Refused):
                    link.link_job(raw, pins_for(raw), context, validator)
                self.assertEqual((registry.project_reads - p0, registry.sha256_calls - s0, validator.calls), (1, 0, 0))

    def test_def6_project_or_sha256_raising_propagates_identical_object(self):
        class Sentinel(Exception):
            pass
        for exc in (Sentinel('p'), AttributeError('p'), Refused('p')):
            with self.subTest(where='project', exc=type(exc).__name__):
                class RaisingProject(ModelRegistryR10):
                    def project(self, name, exc=exc):
                        self.project_reads += 1            # the attempt is counted, then the method raises
                        raise exc
                registry = RaisingProject(); raw = proposal_bytes(ModelRegistryR10()); context = ModelContext(registry)
                p0, s0 = registry.project_reads, registry.sha256_calls
                validator = Counting(copy_callback)
                with self.assertRaises(type(exc)) as caught:
                    link.link_job(raw, pins_for(raw), context, validator)
                self.assertIs(caught.exception, exc)
                self.assertEqual((registry.project_reads - p0, registry.sha256_calls - s0, validator.calls), (1, 0, 0))
        for exc in (Sentinel('s'), AttributeError('s'), Refused('s')):
            with self.subTest(where='sha256', exc=type(exc).__name__):
                class RaisingSha(ModelRegistryR10):
                    def sha256(self, exc=exc):
                        self.sha256_calls += 1
                        raise exc
                registry = RaisingSha(); raw = proposal_bytes(ModelRegistryR10()); context = ModelContext(registry)
                p0, s0 = registry.project_reads, registry.sha256_calls
                validator = Counting(copy_callback)
                with self.assertRaises(type(exc)) as caught:
                    link.link_job(raw, pins_for(raw), context, validator)
                self.assertIs(caught.exception, exc)
                self.assertEqual((registry.project_reads - p0, registry.sha256_calls - s0, validator.calls), (1, 1, 0))


class Successor04MethodQualificationTests(unittest.TestCase):
    """absent or non-callable provider methods refuse with ZERO calls; attempted calls
    that raise (def6) are a different outcome and keep their identity."""

    def test_absent_or_noncallable_project_method_refuses_with_zero_calls(self):
        for shape in ('absent', 'noncallable'):
            with self.subTest(shape=shape):
                registry = ModelRegistryR10(); raw = proposal_bytes(ModelRegistryR10())
                if shape == 'absent':
                    class NoProject:                       # exposes everything except project
                        def __init__(self, inner):
                            self.inner = inner
                        def __getattr__(self, name):
                            if name == 'project':
                                raise AttributeError(name)
                            return getattr(self.inner, name)
                    provider = NoProject(registry)
                else:
                    registry.project = 17                  # present but not callable
                    provider = registry
                context = ModelContext(provider)
                validator = Counting(copy_callback)
                s0, p0 = registry.sha256_calls, registry.project_reads
                with self.assertRaises(Refused) as caught:
                    link.link_job(raw, pins_for(raw), context, validator)
                self.assertIn('context method: project', str(caught.exception))
                self.assertEqual((registry.project_reads - p0, registry.sha256_calls - s0, validator.calls), (0, 0, 0))

    def test_absent_or_noncallable_sha256_method_refuses_with_zero_calls(self):
        for shape in ('absent', 'noncallable'):
            with self.subTest(shape=shape):
                registry = ModelRegistryR10(); raw = proposal_bytes(ModelRegistryR10())
                if shape == 'absent':
                    class NoSha:
                        def __init__(self, inner):
                            self.inner = inner
                        def __getattr__(self, name):
                            if name == 'sha256':
                                raise AttributeError(name)
                            return getattr(self.inner, name)
                    provider = NoSha(registry)
                else:
                    registry.sha256 = 'not a method'
                    provider = registry
                context = ModelContext(provider)
                validator = Counting(copy_callback)
                s0, p0 = registry.sha256_calls, registry.project_reads
                with self.assertRaises(Refused) as caught:
                    link.link_job(raw, pins_for(raw), context, validator)
                self.assertIn('context method: sha256', str(caught.exception))
                # both methods are qualified BEFORE the first project() call: zero reads either way
                self.assertEqual((registry.project_reads - p0, registry.sha256_calls - s0, validator.calls), (0, 0, 0))

    def test_valid_methods_that_raise_are_attempted_calls_not_shape_refusals(self):
        # Contrast with the two cases above: a present callable that raises is CALLED and its exception
        # propagates (def6 covers identity); here only the call count distinguishes the two outcomes.
        class Sentinel(Exception):
            pass
        exc = Sentinel('attempted')
        class RaisingProject(ModelRegistryR10):
            def project(self, name):
                self.project_reads += 1
                raise exc
        registry = RaisingProject(); raw = proposal_bytes(ModelRegistryR10()); context = ModelContext(registry)
        p0 = registry.project_reads
        with self.assertRaises(Sentinel) as caught:
            link.link_job(raw, pins_for(raw), context, Counting(copy_callback))
        self.assertIs(caught.exception, exc)
        self.assertEqual(registry.project_reads - p0, 1)


if __name__ == '__main__':
    unittest.main()
