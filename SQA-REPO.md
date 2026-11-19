# SQA-REPO: Software Quality Assurance Report (COMP 5710/6710, Fall 2026)

**Team:** MILESLAGMAN (Miles Lagman)
**Project:** SLI-KUBE / KubeSec, a static security scanner for Kubernetes manifests (from `slikube.zip`)

> Status: progress draft (2026-11-18). Final version due Dec 01, 2026.

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
_To be completed for the final report._

## 5. Evidence / screenshots
_To be added: screenshots of the Actions runs, the fuzz output and the forensic log._
