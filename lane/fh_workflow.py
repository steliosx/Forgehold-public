#!/usr/bin/python3 -I

# Accepts only a constrained, unambiguous single-job subset of GitHub workflow YAML, so the one agreed job is the
# only job the dispatch can create:
#   - at most 65536 bytes of UTF-8, exactly one YAML document, sha256 == the agreed workflow_sha256;
#   - no anchors, aliases, explicit tags or merge keys anywhere; no duplicate mapping keys at any level;
#   - top level: only name / run-name / on / permissions / concurrency / env / defaults / jobs;
#   - on: exactly workflow_dispatch (scalar, one-item list, or a mapping whose only key is workflow_dispatch with an
#     empty value or an inputs-free mapping);
#   - jobs: exactly one job, whose id is the agreed job;
#   - that job: only name / runs-on / timeout-minutes / steps / permissions / env / defaults / concurrency; so no
#     uses (reusable workflow), strategy (matrix), needs, if, services or container;
#   - runs-on: exactly the labels self-hosted, Linux, X64, forgehold (a flow or block list, each once, no expression);
#   - timeout-minutes: a literal integer 1..6; steps: a non-empty list of mappings.
# Parser: PyYAML (system package python-yaml 6.0.3, /usr/lib/python3.14/site-packages/yaml) with BaseLoader, so every
# scalar stays a string and `on` is never turned into a boolean. Nothing is installed by this file.
#   fh_workflow.py check <workflow-file> <job> <workflow_sha256>   -> exit 0 if accepted, else 1 (reason on stderr)
import hashlib
import re
import sys

import yaml

PYYAML_VERSION = "6.0.3"   # reviewed parser version (python-yaml 6.0.3-2); any other version refuses before effects

LABELS = {"self-hosted", "Linux", "X64", "forgehold"}
TOP = {"name", "run-name", "on", "permissions", "concurrency", "env", "defaults", "jobs"}
JOB_KEYS = {"name", "runs-on", "timeout-minutes", "steps", "permissions", "env", "defaults", "concurrency"}


class Reject(Exception):
    pass


class StrictLoader(yaml.BaseLoader):
    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge" or getattr(key_node, "value", None) == "<<":
                raise Reject("merge key")
            k = self.construct_object(key_node, deep=deep)
            if k in seen:
                raise Reject(f"duplicate key {k!r}")
            seen.add(k)
        return super().construct_mapping(node, deep=deep)


def events_clean(text):
    docs = 0
    for ev in yaml.parse(text, Loader=yaml.BaseLoader):
        if isinstance(ev, yaml.AliasEvent):
            raise Reject("alias")
        if getattr(ev, "anchor", None) is not None:
            raise Reject("anchor")
        if isinstance(ev, (yaml.ScalarEvent, yaml.SequenceStartEvent, yaml.MappingStartEvent)):
            implicit = ev.implicit if isinstance(ev, yaml.ScalarEvent) else (ev.implicit,)
            if ev.tag is not None and not any(implicit):
                raise Reject("explicit tag")
        if isinstance(ev, yaml.DocumentStartEvent):
            docs += 1
    if docs != 1:
        raise Reject("not exactly one document")


def check(raw, job, want_sha):
    if getattr(yaml, "__version__", None) != PYYAML_VERSION:
        raise Reject(f"PyYAML version {getattr(yaml, '__version__', None)} is not the reviewed {PYYAML_VERSION}")
    if len(raw) > 65536:
        raise Reject("too large")
    if hashlib.sha256(raw).hexdigest() != want_sha:
        raise Reject("sha256 mismatch")
    text = raw.decode("utf-8")
    events_clean(text)
    doc = yaml.load(text, Loader=StrictLoader)
    if not isinstance(doc, dict) or set(doc) - TOP or "on" not in doc or "jobs" not in doc:
        raise Reject("top-level keys")
    on = doc["on"]
    if isinstance(on, str):
        ok = on == "workflow_dispatch"
    elif isinstance(on, list):
        ok = on == ["workflow_dispatch"]
    elif isinstance(on, dict):
        v = on.get("workflow_dispatch", None)
        ok = set(on) == {"workflow_dispatch"} and (v == "" or (isinstance(v, dict) and "inputs" not in v))
    else:
        ok = False
    if not ok:
        raise Reject("on is not exactly workflow_dispatch")
    jobs = doc["jobs"]
    if not isinstance(jobs, dict) or list(jobs) != [job]:
        raise Reject("jobs is not exactly the agreed job")
    j = jobs[job]
    if not isinstance(j, dict) or set(j) - JOB_KEYS or "runs-on" not in j or "steps" not in j or "timeout-minutes" not in j:
        raise Reject("job keys")
    ro = j["runs-on"]
    if not isinstance(ro, list) or len(ro) != len(LABELS) or set(ro) != LABELS:
        raise Reject("runs-on is not exactly the forgehold labels")
    tm = j["timeout-minutes"]
    if not isinstance(tm, str) or not re.fullmatch(r"[1-6]", tm):
        raise Reject("timeout-minutes not a literal 1..6")
    steps = j["steps"]
    if not isinstance(steps, list) or not steps or not all(isinstance(s, dict) for s in steps):
        raise Reject("steps")


def main(a):
    if len(a) != 4 or a[0] != "check" or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", a[2]) or not re.fullmatch(r"[0-9a-f]{64}", a[3]):
        return 64
    try:
        with open(a[1], "rb") as f:
            raw = f.read(65537)
        check(raw, a[2], a[3])
    except (OSError, UnicodeDecodeError, yaml.YAMLError, Reject, TypeError) as e:  # TypeError: e.g. an unhashable runs-on item
        print(f"fh_workflow: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
