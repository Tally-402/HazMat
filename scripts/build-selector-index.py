#!/usr/bin/env python3
"""Rebuild register/selectors.json: a bare-selector to signature index.

A comfort reading for the uncovered-selector list on a sheet, nothing more: a name here is
keccak(signature) and no evidence about the contract. It is built from the verified sources
each confirmation record already fetched, so it stays in step with the register.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'matcher'))

from hazmat import derive                                       # noqa: E402

INDEX = ROOT / 'register' / 'selectors.json'


def main():
    # merged into what is already there, not replaced: a name should not disappear just
    # because a work directory was cleaned, and this index claims nothing about the code
    existing = json.loads(INDEX.read_text()) if INDEX.is_file() else {'selectors': {}}
    out = {'note': existing.get('note', 'comfort reading for the uncovered list: selector to signature. A convenience index, not verification; a name here is keccak(signature) and nothing more.'),
           'count': 0, 'selectors': dict(existing.get('selectors') or {})}
    collisions, missing = [], []
    for record in sorted((ROOT / 'confirmations').glob('HZ-*.json')):
        rec = json.loads(record.read_text())
        workdir = ROOT / str(rec.get('workdir') or '')
        sources = sorted((workdir / 'src').rglob('*.sol')) if workdir.is_dir() else []
        if not sources:
            missing.append(rec['placard'])
            continue
        for signature in derive.signatures([str(p) for p in sources]):
            selector = derive.selector(signature)[2:]
            known = out['selectors'].get(selector)
            if known and known != signature:
                collisions.append((selector, known, signature))
            out['selectors'][selector] = signature
    out['count'] = len(out['selectors'])
    INDEX.write_text(json.dumps(dict(sorted(out.items())), indent=1, sort_keys=True) + '\n')
    print('%d selectors from %d source trees' % (out['count'], len(list((ROOT / 'confirmations').glob('HZ-*.json'))) - len(missing)))
    if missing:
        print('  no local sources for: %s' % ', '.join(missing))
    if collisions:
        print('  selector collisions: %s' % collisions)
    return 0


if __name__ == '__main__':
    sys.exit(main())
