# SQA-REPO: Software Quality Assurance Report (COMP 5710/6710, Fall 2026)

**Team:** MILESLAGMAN (Miles Lagman)
**Project:** SLI-KUBE / KubeSec, a static security scanner for Kubernetes manifests (from `slikube.zip`)

> Status: near-final (2026-11-22). Screenshots still to be added; due Dec 01, 2026.

## 1. Fuzzing (`fuzz.py`)

`fuzz.py` fuzzes 10 methods with random and mutated inputs. It uses a fixed seed (6710) so runs are reproducible, and it runs 500 inputs per method by default. Inputs include special strings (empty, NUL, 10k chars, path traversal, format strings, Unicode), random scalars of every type, random nested dict/list structures that look like parsed YAML, and mutated or random-byte YAML files. Each exception is grouped by method and exception type and written to `fuzz_report.csv`. The script always exits 0 so CI can upload the report; crashes are treated as findings.

| # | Method | Result |
|---|--------|--------|
| 1 | `parser.checkIfWeirdYAML` | **crash**: `TypeError` on non-string input |
| 2 | `parser.keyMiner` | ok |
| 3 | `parser.getKeyRecursively` | ok |
| 4 | `parser.getValuesRecursively` | ok |
| 5 | `parser.getValsFromKey` | ok |
| 6 | `scanner.checkIfValidSecret` | ok |
| 7 | `scanner.scanForSecrets` | ok |
| 8 | `graphtaint.constructHelmString` | **crash**: `TypeError`/`ValueError` when the tuple is not a 3-tuple of strings |
| 9 | `graphtaint.getValidTaints` | **crash**: `ValueError`/`TypeError`/`AttributeError` on malformed match lists |
| 10 | `parser.loadMultiYAML` | **crash**: `RecursionError` and `TypeError` on *valid* YAML input (see below) |

### Bugs found
1. **Self-referential YAML anchor crashes the scanner (DoS).** A one-line manifest `&a [*a]` makes `parser.loadMultiYAML` → `find_json_path_keys` recurse forever (`RecursionError`). A scanned repository that contains such a file aborts the whole scan.
2. **Null mapping key crashes the scanner.** YAML such as `~: value` produces a `None` key, and `find_json_path_keys` calls `regex.match(None)`, which raises `TypeError`.
3. **Missing input validation.** `checkIfWeirdYAML`, `constructHelmString` and `getValidTaints` assume a specific type or shape and raise when they get anything else.

Other defects found while setting up:
- `main.py` used `typer` and `Path` without importing them, so the tool and `TEST_INTEGRATION.py` failed at import. We fixed this.
- `parser.show_line_for_paths` shells out to the undocumented external `yq` binary.
- `parser.show_line_for_paths` read `key_jsonpath_mapping[key]` in a debug `print` *before* the code checked whether the key exists. When run on the project's own `TEST_ARTIFACTS`, the full scan crashed with `KeyError: 'Unconfined'`. CI exposed this; we fixed it with `.get(key)`.
- Two Helm fixtures (`helm.values.yaml`, `helm.stackgres.yaml`) contained a real-format Grafana API key in a YAML comment, and GitHub push protection blocked the push. Because it was only in a comment, the scanner never saw it. We redacted it.
- `TEST_GRAPH.py` and many `TEST_SCANNING.py` cases use hard-coded absolute paths from the original author's machine (`/Users/arahman/...`). As a result, 27/27 graph tests and 65/115 scanning tests error out.

## 2. Forensics (`forensics.py`)

`forensics.py` provides a shared logger. Each log line records the timestamp, level, PID, OS user, the `module.function` that wrote it, and a message. Lines go to `forensics/slikube_forensics.log`; the `SLIKUBE_LOG` environment variable overrides the path. Secret *values* are never logged, only the key names where secrets were found.

Instrumented methods (10):

| # | Method | What is logged |
|---|--------|----------------|
| 1 | `parser.readYAMLAsStr` | file read and its size |
| 2 | `parser.checkParseError` | whether the parse succeeded, and files skipped |
| 3 | `parser.loadMultiYAML` | file loaded, YAML/Unicode errors, number of documents |
| 4 | `parser.checkIfValidK8SYaml` | Kubernetes-manifest classification and key count |
| 5 | `scanner.getYAMLFiles` | directory searched and number of YAML files |
| 6 | `scanner.scanForSecrets` | key names of hard-coded secret candidates (WARNING) |
| 7 | `scanner.scanSingleManifest` | secret, template and taint finding counts per manifest |
| 8 | `scanner.runScanner` | scan start/end, invalid and "weird" files skipped, totals |
| 9 | `graphtaint.getHelmTemplateContent` | Helm template directory and template count |
| 10 | `main.main` | tool invocation, target directory, output files |

## 3. Continuous Integration (`.github/workflows/sqa.yml`)

GitHub Actions runs on every push, on pull requests, and on manual dispatch:
1. Set up Python 3.11 and install the dependencies (`yq` is preinstalled on `ubuntu-latest`).
2. Run the unit tests (`TEST_PARSING.py`).
3. Run `fuzz.py`.
4. Run SLI-KUBE on `TEST_ARTIFACTS`, which writes the forensic log.
5. Upload `fuzz_report.csv`, the forensic log, the CSV/SARIF results and the scan output as the `sqa-evidence` artifact.

## 4. Lessons learned

**Fuzzing**
- **Cheap random fuzzing still finds real bugs.** The fuzzer took a few hours to write and runs in seconds, yet it found two crashes reachable from ordinary YAML files: the self-referential anchor and the null key. For a security scanner these are serious, because anyone who controls a single file in the scanned repository can abort the whole scan and hide every other finding.
- **Structure-aware inputs beat pure noise.** Random strings mostly exercised type checks, while the dict/list generator and the mutated YAML seeds reached the deeper parsing logic, which is where the more serious bugs were. Seeding the fuzzer with realistic inputs mattered more than raising the iteration count.
- **Not every crash has the same weight.** Most crash signatures came from passing the wrong type to internal helpers such as `constructHelmString`. Those show that the code has no defensive checks, but normal callers never trigger them. Separating "reachable from user input" from "reachable only through API misuse" was needed to report the results honestly.
- **A fixed seed makes results reproducible**, so a crash seen in CI can be reproduced locally and the report numbers stay stable between runs.

**Forensics**
- **Deciding what to log is a design decision.** The most useful entries record decisions the tool makes on its own: which files were skipped as invalid or "weird", what each file was classified as, and how many findings each manifest produced. Without these, a scan that reports zero problems is indistinguishable from a scan that silently skipped everything.
- **Logs can leak secrets themselves.** `scanForSecrets` finds hard-coded passwords and tokens. Logging the values would copy those secrets into a log file that is uploaded as a CI artifact, so we log only the key names.
- **A central logger keeps logging consistent.** Putting the format (time, PID, user, method) in one module kept the 10 instrumented methods short and their output uniform.

**Continuous integration**
- **CI finds problems that local runs hide.** The full scan worked well enough on our machine, but its first CI run crashed with a `KeyError` in `show_line_for_paths`. The clean environment also revealed an undocumented dependency: the code shells out to the external `yq` binary.
- **Platform security checks are part of QA.** GitHub push protection blocked our first push because test fixtures contained a real-format API key. A tool meant to *detect* hard-coded secrets had shipped them in its own test data.
- **Treat fuzz crashes as findings in CI.** We made `fuzz.py` exit 0 and upload its report, rather than fail the build, because the known bugs are documented rather than fixed. Otherwise every build would be red and real regressions would be harder to notice.

**General**
- **Inherited code has inherited debt.** Before any new QA work, the project could not even start (`main.py` had missing imports), and most of the existing test suite depended on files from the original author's computer. These tests looked like coverage but checked nothing on any other machine. Making the tests run anywhere is a prerequisite for every other QA activity.

## 5. Evidence / screenshots
_To be added: screenshots of the Actions runs, the fuzz output and the forensic log._
