"""Batch mode: scan many targets from a file, write a sheet for each.

Each line is an address, 0x-hex, or a path to a file of code. Blank lines and
lines starting with # are skipped.
"""
import argparse
import json
import os
import sys
from pathlib import Path

from . import chains, match, sds


def lines(path):
    out = []
    for raw in open(path).read().splitlines():
        line = raw.split('#')[0].strip()
        if line:
            out.append(line)
    return out


def run(path, register, rpc=None, chain=None, sheet_dir=None, quiet=False, as_='auto'):
    if chain:
        rpc = chains.endpoint(chain)
    reports = []
    for target in lines(path):
        try:
            report = match.scan(target, register, rpc, as_=as_)
        except match.MatchError as exc:
            report = {'target': target, 'state': 'blocked', 'error': str(exc), 'matches': []}
        if sheet_dir:
            # a clean sheet is still a document, so one is always written
            os.makedirs(sheet_dir, exist_ok=True)
            page, digest = sds.render(report)
            stem = report.get('code_sha256', target)[:18].replace('0x', '')
            name = os.path.join(sheet_dir, stem + '.html')
            open(name, 'w').write(page)
            report['sheet'] = name
            report['sheet_digest'] = digest
        reports.append(report)
        if not quiet:
            ids = [m['id'] for m in report.get('matches', [])]
            print('%-44s %s' % (target, ', '.join(ids) if ids else 'no placard matched'))
    return reports


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat batch')
    parser.add_argument('--file', required=True)
    parser.add_argument('--register', default='register/placards')
    parser.add_argument('--chain', default=None, choices=sorted(chains.CHAINS))
    parser.add_argument('--rpc', default=None)
    parser.add_argument('--sheet-dir', default=None)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--as', dest='as_', default='auto', choices=['auto', 'address', 'code'])
    args = parser.parse_args(argv)
    reports = run(args.file, args.register, args.rpc, args.chain, args.sheet_dir, quiet=args.json, as_=args.as_)
    if args.json:
        print(json.dumps(reports, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
