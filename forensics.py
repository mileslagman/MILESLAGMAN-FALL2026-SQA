'''
forensics.py -- shared forensic logger for KubeSec (SLI-KUBE).

Every instrumented method records who/what/when: the method name, the
inputs it was given (files scanned, key counts), its outcome, and any
error. Entries go to forensics/slikube_forensics.log (override with the
SLIKUBE_LOG env var) so an analyst can reconstruct what the tool
analyzed and what it concluded after the fact.
'''
import getpass
import logging
import os

LOG_FILE = os.environ.get(
    'SLIKUBE_LOG',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forensics', 'slikube_forensics.log'),
)


def _user():
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 -- no user in some CI containers
        return 'unknown'


def getLogger():
    logger = logging.getLogger('slikube.forensics')
    if not logger.handlers:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)s | pid=%(process)d | user=' + _user() + ' | %(module)s.%(funcName)s | %(message)s'))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
