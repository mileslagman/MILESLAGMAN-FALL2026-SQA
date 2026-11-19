'''
fuzz.py -- random/mutation fuzzing for 10 KubeSec (SLI-KUBE) methods.

Run:  python fuzz.py [iterations]
Every unexpected exception is recorded as a crash in fuzz_report.csv and
summarized on stdout. The script exits 0 so CI keeps going and uploads the
report; crashes are *findings*, not build failures.
'''
import csv
import os
import random
import string
import sys
import tempfile
import traceback

import parser
import scanner
import graphtaint

SEED = 6710
random.seed(SEED)

ITERATIONS = int(sys.argv[1]) if len(sys.argv) > 1 else 500
REPORT_FILE = 'fuzz_report.csv'

# ---------------------------------------------------------------- generators
SPECIAL_STRINGS = [
    '', ' ', '\x00', '\n', '../../etc/passwd', '%s%s%n', "'; DROP TABLE x;--",
    'A' * 10000, '‮\u0000￿', '😀', 'password', 'user', 'secret-key',
    '-----BEGIN RSA PRIVATE KEY-----', '{{ .Values.x }}', 'http://x', 'null',
    '.github/workflows/ci.yml', 'values.yaml', 'helm/chart/values.yaml',
]


def rand_str(max_len=40):
    if random.random() < 0.3:
        return random.choice(SPECIAL_STRINGS)
    alphabet = string.printable + 'äöü€漢字\x00'
    return ''.join(random.choice(alphabet) for _ in range(random.randint(0, max_len)))


def rand_scalar():
    return random.choice([
        rand_str, lambda: random.randint(-2**63, 2**63), lambda: random.random() * 1e308,
        lambda: None, lambda: True, lambda: False, lambda: b'\xff\xfe', lambda: float('nan'),
    ])()


def rand_obj(depth=0):
    '''random nested dict/list structure resembling a parsed YAML document'''
    r = random.random()
    if depth > 4 or r < 0.35:
        return rand_scalar()
    if r < 0.7:
        d = {}
        for _ in range(random.randint(0, 5)):
            key = random.choice([rand_str, lambda: random.randint(0, 9), lambda: None, lambda: (1, 2)])()
            d[key] = rand_obj(depth + 1)
        return d
    return [rand_obj(depth + 1) for _ in range(random.randint(0, 5))]


def rand_any():
    return random.choice([rand_scalar, rand_obj, lambda: [rand_str()], lambda: object()])()


def rand_tuple_list():
    return random.choice([
        lambda: [(rand_str(), rand_str()) for _ in range(random.randint(0, 4))],
        lambda: [tuple(rand_any() for _ in range(random.randint(0, 3)))],
        rand_any,
    ])()


def rand_hiera():
    return random.choice([
        lambda: (rand_str(), rand_str(), rand_any()),
        lambda: (rand_any(), rand_any(), rand_any()),
        lambda: tuple(rand_str() for _ in range(random.randint(0, 4))),
        rand_any,
    ])()


def rand_yaml_file():
    '''write a random (often malformed) YAML file and return its path'''
    fd, path = tempfile.mkstemp(suffix='.yaml')
    seeds = [
        'apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n',
        'apiVersion: v1\nkind: Secret\ndata:\n  password: hunter2\n---\nkind: X\n',
        ': : :\n- [\n', '\t\tkey: value\n', '---\n---\n', '&a [*a]\n',
    ]
    body = random.choice(seeds)
    if random.random() < 0.6:   # mutate
        body = list(body)
        for _ in range(random.randint(1, 10)):
            pos = random.randint(0, len(body))
            body.insert(pos, random.choice(string.printable + '\x00\xff{}[]:&*!|>'))
        body = ''.join(body)
    with os.fdopen(fd, 'wb') as f:
        f.write(body.encode('utf-8', 'surrogatepass') if random.random() < 0.9 else os.urandom(64))
    return path


# ------------------------------------------------------------------ targets
def t_checkIfWeirdYAML():
    parser.checkIfWeirdYAML(rand_any())


def t_keyMiner():
    parser.keyMiner(rand_obj(), rand_scalar())


def t_getKeyRecursively():
    parser.getKeyRecursively(rand_obj(), [])


def t_getValuesRecursively():
    list(parser.getValuesRecursively(rand_obj()))


def t_getValsFromKey():
    parser.getValsFromKey(rand_obj(), rand_scalar(), [])


def t_checkIfValidSecret():
    scanner.checkIfValidSecret(rand_any())


def t_scanForSecrets():
    scanner.scanForSecrets(rand_obj())


def t_constructHelmString():
    graphtaint.constructHelmString(rand_hiera())


def t_getValidTaints():
    graphtaint.getValidTaints(rand_tuple_list())


def t_loadMultiYAML():
    path = rand_yaml_file()
    try:
        parser.loadMultiYAML(path)
    finally:
        os.remove(path)


TARGETS = [
    ('parser.checkIfWeirdYAML', t_checkIfWeirdYAML),
    ('parser.keyMiner', t_keyMiner),
    ('parser.getKeyRecursively', t_getKeyRecursively),
    ('parser.getValuesRecursively', t_getValuesRecursively),
    ('parser.getValsFromKey', t_getValsFromKey),
    ('scanner.checkIfValidSecret', t_checkIfValidSecret),
    ('scanner.scanForSecrets', t_scanForSecrets),
    ('graphtaint.constructHelmString', t_constructHelmString),
    ('graphtaint.getValidTaints', t_getValidTaints),
    ('parser.loadMultiYAML', t_loadMultiYAML),
]


def main():
    crashes = {}   # (method, exc type, exc msg-prefix) -> [count, example traceback]
    devnull = open(os.devnull, 'w')
    for name, fn in TARGETS:
        for _ in range(ITERATIONS):
            real_stdout, sys.stdout = sys.stdout, devnull   # silence tool's prints
            try:
                fn()
            except Exception as e:  # noqa: BLE001 -- we want every crash
                # group by (method, exception type); keep the first message/traceback as the example
                key = (name, type(e).__name__)
                entry = crashes.setdefault(key, [0, str(e)[:80], traceback.format_exc(limit=-2)])
                entry[0] += 1
            finally:
                sys.stdout = real_stdout

    with open(REPORT_FILE, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['method', 'exception', 'message', 'count', 'traceback'])
        for (m, et), (cnt, msg, tb) in sorted(crashes.items()):
            w.writerow([m, et, msg, cnt, tb])

    print(f'Fuzzed {len(TARGETS)} methods x {ITERATIONS} inputs (seed {SEED})')
    crashed = sorted({k[0] for k in crashes})
    for name, _ in TARGETS:
        n = sum(v[0] for k, v in crashes.items() if k[0] == name)
        print(f'  {"CRASH" if n else "ok   "}  {name:34s} {n} crashing inputs')
    print(f'{len(crashes)} distinct crash signatures in {len(crashed)} methods -> {REPORT_FILE}')
    for (m, et), (cnt, msg, _) in sorted(crashes.items()):
        print(f'  - {m}: {et} x{cnt}, e.g. {msg!r}')


if __name__ == '__main__':
    main()
