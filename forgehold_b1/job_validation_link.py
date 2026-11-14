"""Link a disabled model job proposal to a caller-selected existing validator.

The caller supplies existing_context unchanged and a validator callable. Source
hashes in data pins do not authenticate either. No queue, ledger, storage or
controller is constructed here; result flags describe only this module's actions.

Required provider methods are checked before calls. Project fields are captured
once, checked and encoded before provider hash reads can mutate the row. Local
malformed data is refused. Provider and validator exceptions otherwise propagate;
provider effects and adversarial property getters remain outside this boundary.
"""
from .data_rules import decode, digest, encode, exact, hex64, integer, require, Refused
from .quality_job import (PROJECT, JOB_KEYS, PROFILE_SHA256, INVENTORY_SHA256,
                                   INPUT_TUPLE_SHA256)


COMPONENT_CEILING = 16384
AGGREGATE_LIMIT = 65536
PROPOSAL_KEYS = ('status', 'job', 'activation', 'admitted', 'enrollment_established',
                 'authority_pins_verified', 'usable_for_live_submission',
                 'queue_or_ledger_mutated', 'controller_constructed')
PROPOSAL_FLAGS = PROPOSAL_KEYS[2:]
JOB_LITERALS = {'project': PROJECT, 'profile': 'LOCAL_QUALITY', 'mode': 'PORTABLE',
                'profile_sha256': PROFILE_SHA256, 'input_tuple_sha256': INPUT_TUPLE_SHA256,
                'source_inventory_sha256': INVENTORY_SHA256}
JOB_HEX = ('request_id', 'owner_grant_sha256', 'runtime_A', 'runtime_M', 'runtime_C')
PIN_KEYS = ('proposal_sha256', 'profile_sha256', 'source_inventory_sha256',
            'input_tuple_sha256', 'validator_reference')
REFERENCE_KEYS = ('source_sha256', 'path_label')
SELECTED_PROFILE = ('LOCAL_QUALITY', 'PORTABLE', PROFILE_SHA256, INVENTORY_SHA256)
RESOURCE_PROFILES = ('PRODUCTION_PORTABLE', 'LIFECYCLE_ONE_CASE_V1')
RESULT_FLAGS = ('activation', 'admitted', 'usable_for_live_submission',
                'authority_pins_verified', 'enrollment_established', 'policy_qualified',
                'callback_authenticated', 'snapshot_complete', 'queue_or_ledger_mutated',
                'controller_constructed')


def _account(before, next_bound):
    """Contract 4b: refuse before producing a component that could exceed the aggregate."""
    integer(before, 0, AGGREGATE_LIMIT)
    integer(next_bound, 1, COMPONENT_CEILING)
    require(before + next_bound <= AGGREGATE_LIMIT, 'aggregate serialized byte bound')
    return before


def _bounded_text(value, limit):
    require(type(value) is str and 1 <= len(value) <= limit and value.isascii(),
            'bounded ASCII text')
    return value


def _decode_proposal(raw):
    """Bridge-owned boundary: malformed bytes become this module's Refused; Refused passes through."""
    try:
        return decode(raw, COMPONENT_CEILING, 4096)
    except Refused:
        raise
    except (UnicodeDecodeError, ValueError) as error:   # json.JSONDecodeError is a ValueError
        raise Refused('malformed proposal bytes') from error


def _proposal(raw):
    """Decode and check the exact R60 disabled proposal; return the private baseline job."""
    require(type(raw) is bytes and 0 < len(raw) <= COMPONENT_CEILING, 'proposal byte bound')
    value = _decode_proposal(raw)
    exact(value, PROPOSAL_KEYS)
    require(value['status'] == 'SOURCE_DISABLED_JOB_PROPOSAL', 'disabled proposal status')
    for flag in PROPOSAL_FLAGS:
        require(value[flag] is False, 'literal false proposal flag: ' + flag)
    job = exact(value['job'], JOB_KEYS)
    for key, literal in JOB_LITERALS.items():
        require(type(job[key]) is str and job[key] == literal, 'fixed B1 job literal: ' + key)
    for key in JOB_HEX:
        hex64(job[key])
    # Canonical round-trip: comparison only; these bytes are discarded and not counted (4b).
    require(encode(value, COMPONENT_CEILING) == raw, 'canonical proposal bytes')
    return dict(job)


def _pins(pins, raw):
    exact(pins, PIN_KEYS)
    require(hex64(pins['proposal_sha256']) == digest(raw), 'independent proposal pin')
    require(hex64(pins['profile_sha256']) == PROFILE_SHA256
            and hex64(pins['source_inventory_sha256']) == INVENTORY_SHA256
            and hex64(pins['input_tuple_sha256']) == INPUT_TUPLE_SHA256,
            'independently selected B1 profile/inventory/input tuple')
    reference = exact(pins['validator_reference'], REFERENCE_KEYS)
    hex64(reference['source_sha256'])  # DATA label; authenticates nothing.
    _bounded_text(reference['path_label'], 240)
    return {'source_sha256': reference['source_sha256'], 'path_label': reference['path_label']}


def _present(obj, name):
    # A missing field, a None value, or a property that raises AttributeError all become this
    # module's own Refused('MISSING ...') before the callback; the original AttributeError from a
    # raising property is not preserved here. Method CALLS (project(), sha256()) are never wrapped.
    value = getattr(obj, name, None)
    require(value is not None, 'MISSING context field: ' + name)
    return value


def _method(obj, name):
    # successor-04: an ABSENT method attribute or a present NON-CALLABLE one is a malformed provider
    # context and becomes this module's Refused with ZERO calls made; the resolved callable is then
    # called outside any handler, so an exception raised by a valid method call keeps its identity.
    # Callability is a shape check only; it authenticates nothing about the method.
    method = getattr(obj, name, None)
    require(method is not None, 'MISSING context method: ' + name)
    require(callable(method), 'non-callable context method: ' + name)
    return method


def _observe(existing_context):
    """Contract 3: one project() read and one sha256() read; named fields captured once.

    Restates the R60 adapter checks (_registry_snapshot :99-109) inline. Every named field is read
    exactly once into a local, checked for exact type and literal, and ONLY those locals are
    encoded; sha256() is called after the captures. Exceptions raised by project() or sha256()
    themselves propagate, as in R60; missing/None fields are this module's Refused.
    """
    registry = _present(existing_context, 'project_registry')
    project_method = _method(registry, 'project')            # shape checks; zero calls so far
    sha256_method = _method(registry, 'sha256')
    project = project_method(PROJECT)                        # one read; exceptions propagate
    project_id = _present(project, 'project_id')             # each field captured exactly once
    kind = _present(project, 'kind')
    enabled = getattr(project, 'enabled', None)
    profiles = _present(project, 'profiles')
    require(type(project_id) is str and project_id == PROJECT, 'project identity literal')
    require(type(kind) is str and kind == 'APPLICATION', 'application project kind literal')
    require(enabled is True, 'missing/disabled application registry membership')
    require(type(profiles) is tuple and 0 < len(profiles) <= 8, 'bounded immutable profiles')
    for item in profiles:
        require(type(item) is tuple and len(item) == 4, 'existing profile row shape')
        _bounded_text(item[0], 64); _bounded_text(item[1], 64)  # pre-serialization bounds (3)
        hex64(item[2]); hex64(item[3])
    require(len(set(item[:3] for item in profiles)) == len(profiles), 'duplicate profile key')
    require(sum(item == SELECTED_PROFILE for item in profiles) == 1,
            'conflicting profile/inventory binding')
    resource_profile = _present(existing_context, 'resource_profile')
    require(type(resource_profile) is str and resource_profile in RESOURCE_PROFILES,
            'existing resource profile name')  # recorded, not judged
    resource_policy = hex64(_present(registry, 'resource_policy_sha256'))
    owner_adoption = hex64(_present(registry, 'owner_adoption_sha256'))
    enrollment = hex64(_present(registry, 'enrollment_sha256'))
    registry_sha256 = hex64(sha256_method())                # one read, after all captures
    snapshot = {'registry_sha256': registry_sha256,
                'resource_policy_sha256': resource_policy,
                'owner_adoption_sha256': owner_adoption,
                'enrollment_sha256': enrollment,
                'project_id': project_id, 'kind': kind, 'enabled': enabled, 'profiles': profiles,
                'resource_profile': resource_profile}
    return encode(snapshot, COMPONENT_CEILING), resource_profile


def _same_as_baseline(candidate, baseline):
    exact(candidate, JOB_KEYS)
    for key in JOB_KEYS:
        require(type(candidate[key]) is type(baseline[key]) and candidate[key] == baseline[key],
                'validated job differs from private baseline: ' + key)


def link_job(proposal_raw, independent_pins, existing_context, validator):
    """Pass a detached copy of the disabled job to the selected validator exactly once.

    Refuses before the callback on any schema/pin/context/snapshot fault; propagates the
    callback's exception unchanged (no handler, no retry, no rollback); refuses after it if
    the argument or the returned object differs from the private baseline or the second
    observation differs from the first. Returns SOURCE_JOB_VALIDATION_LINK_ONLY data; it is
    not admission, qualification, enrollment, authentication, dispatch or publication.
    """
    baseline = _proposal(proposal_raw)
    before = len(proposal_raw)                                   # component 1
    reference = _pins(independent_pins, proposal_raw)
    before = _account(before, COMPONENT_CEILING) + len(encode(independent_pins, COMPONENT_CEILING))  # 2
    before = _account(before, COMPONENT_CEILING) + len(encode(baseline, COMPONENT_CEILING))          # 3
    require(existing_context is not None, 'existing validator context MISSING')
    require(callable(validator), 'selected validator MISSING')
    _account(before, COMPONENT_CEILING)
    observation_1, resource_profile = _observe(existing_context)                                     # 4
    before += len(observation_1)
    argument = dict(baseline)
    returned = validator(argument, existing_context)             # exactly once; no handler
    _same_as_baseline(argument, baseline)
    _same_as_baseline(returned, baseline)
    _account(before, COMPONENT_CEILING)
    observation_2, _ = _observe(existing_context)                                                    # 5
    before += len(observation_2)
    require(observation_2 == observation_1, 'registry metadata changed during validation')
    _account(before, COMPONENT_CEILING)
    result = {'status': 'SOURCE_JOB_VALIDATION_LINK_ONLY', 'job': dict(baseline),
              'proposal_sha256': digest(proposal_raw), 'snapshot_sha256': digest(observation_1),
              'validator_reference': reference, 'resource_profile_observed': resource_profile,
              'serialized_bytes_before_result': before,     # components 1-5 only (4b)
              'flag_scope': 'BRIDGE_OWN_ACTIONS_ONLY'}
    for flag in RESULT_FLAGS:
        result[flag] = False
    result_bytes = encode(result, COMPONENT_CEILING)             # encoded exactly once
    _account(before, len(result_bytes))                          # full aggregate: checked, not reported
    return result


def dispatch(*args, **kwargs):
    raise Refused('SOURCE_DISABLED: executor/requester/grant/guardian/clock/admission MISSING; no enqueue/dispatch')


def publish_result(*args, **kwargs):
    raise Refused('SOURCE_DISABLED: authenticated result publisher/custody/disposition MISSING')
