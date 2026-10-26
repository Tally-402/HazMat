"""Self-check: fire each placard on its own target, stay quiet on the others.

Every listed address is also a negative control for every placard it does not
expect, so a matcher that fires on everything fails here.
"""
import argparse
import json
import sys
from pathlib import Path

from . import match

ROOT = Path(__file__).resolve().parents[2]
CONTROLS = ROOT / 'register' / 'controls.json'


def check(controls_path=CONTROLS, register=None):
    entries = json.loads(Path(controls_path).read_text())['addresses']
    register = register or str(ROOT / 'register' / 'placards')
    failures = []
    for entry in entries:
        report = match.scan(entry['target'], register, entry.get('rpc'), entry.get('family', 'evm'))
        got = sorted(m['id'] for m in report['matches'])
        want = sorted(entry['expect'])
        ok = got == want
        print('%-6s %s  expect %s  got %s' % ('PASS' if ok else 'FAIL', entry['target'], want, got))
        if not ok:
            failures.append(entry['target'])
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat selfcheck')
    parser.add_argument('--register', default=None)
    parser.add_argument('--controls', default=None)
    args = parser.parse_args(argv)
    failures = check(args.controls or CONTROLS, args.register)
    print('%d failures' % len(failures))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
