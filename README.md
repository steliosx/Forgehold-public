# Forgehold

Forgehold explores a controlled CI execution lane built around Preloop and SmolVM: explicit job inputs, source bindings, bounded execution, and retained evidence for independent review.

**This is a source preview with synthetic examples, not an installable runner or a qualified production deployment.** Its immediately usable CI is the Python unit suite on standard GitHub-hosted runners. Those tests do not boot a VM, exercise a real engine, or prove isolation or cleanup on a live host.

## Run the unit tests

Use Python 3.14 on Linux. The suites use the standard library and require no dependency installation:

```sh
python3 -I -B -m unittest discover -s tests -t . -v
python3 -I -B -m unittest discover -s wrapper/tests -t . -v
```

The suites contain 80 adapter/link/queue tests and 76 supervisor tests. One filesystem-permission test is skipped if run as root; use an ordinary user for the complete check. Hosted CI runs on push to `main` or `release-preview/**`, pull requests, and manual dispatch.

## Source map

- `forgehold_b1/`: strict data validation and a model adapter. A valid model result cannot submit a live job or publish a check.
- `wrapper/`: a bounded test supervisor and mock-based tests for framing, custody, errors and deadlines. Its receipt alone cannot prove a successful outer execution.
- `lane/`: reference helpers for admission, queue handling, workflow validation, host inspection and signed review evidence. These are unconfigured operational source, not a deployment package.
- `profiles/` and `fixtures/`: disabled profiles and synthetic project data. The reported tool versions and PASS records are model inputs, not results from executing those tools.
- `examples/deployment/`: inactive shell and service references. Shell examples exit before performing any operation; service examples have a deliberately unmet activation condition.

## Scope and limitations

The adapter intentionally binds one synthetic project rather than offering a general enrollment API. No private project inventory, operational run record, mailbox key, credential, active authority record or runtime image is distributed. No runtime dependencies are installed by CI.

Source review, unit-test results, runtime qualification, and permission to operate a deployment are separate. A deployment needs its own reviewed configuration, current dependency/security assessment, explicit authority, signed identity setup, resource policy and end-to-end evidence. Nothing in this preview authorizes activation or claims that arbitrary GitHub Actions workflows are supported.

See [the architecture](docs/ARCHITECTURE.md), [release scope](docs/RELEASE-SCOPE.md), and [security reporting](SECURITY.md).

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Preloop and SmolVM are separately distributed upstream projects with their own licenses. They are not vendored here.
