"""Re-derive what a sheet and a record claim, without trusting their producer."""
import argparse
import json
import re
import sys
from pathlib import Path

from . import anchor as anchor_mod
from . import chains, match, paths, sds


class VerifyError(Exception):
    pass


def verify_sheet(path, expect=None, anchor=None):
    page = Path(path).read_text()
    claimed, recomputed, ok = sds.verify(page, expect)
    checks = [
        {'check': 'the sheet carries a digest', 'ok': bool(claimed)},
        {'check': 'the digest re-derives from the sheet bytes', 'ok': claimed == recomputed},
        {'check': 'the digest matches the one supplied', 'ok': expect is None or claimed == expect},
    ]
    # if the sheet names an epoch, that epoch's record must back it - not the newest one,
    # or publishing a new epoch would invalidate every sheet already handed out
    named = re.search(r'register \d+ placards v(0x[0-9a-f]{16})', page)
    claimed_epoch = re.search(r'anchor epoch (\d+) root (0x[0-9a-f]{64})', page)
    record = anchor
    if record is None and claimed_epoch:
        try:
            record = anchor_mod.load_epoch(int(claimed_epoch.group(1)))
        except anchor_mod.AnchorError:
            record = None
    if record is None:
        record = match.latest_anchor()
    if named and record:
        checks.append({'check': 'the register digest the sheet names is that epoch\'s',
                       'ok': named.group(1) == record.get('register_digest'),
                       'sheet': named.group(1), 'epoch': record.get('epoch'), 'root': record.get('root')})
    if claimed_epoch and record:
        checks.append({'check': 'the epoch root the sheet names is that epoch\'s root',
                       'ok': claimed_epoch.group(2) == record.get('root'), 'epoch': record.get('epoch')})
    return {'kind': 'sheet', 'file': paths.display(path), 'claimed': claimed, 'recomputed': recomputed,
            'expected': expect, 'ok': ok and all(c['ok'] for c in checks), 'checks': checks}


def verify_record(path, rpc=None, chain='mainnet'):
    record = json.loads(Path(path).read_text())
    target = record.get('target')
    checks = []
    stages = record.get('stages', {})
    for stage in ('fetch', 'build', 'compare', 'probe'):
        if stage in stages:
            checks.append({'check': 'stage %s ok' % stage, 'ok': stages[stage].get('state') == 'ok'})
    checks.append({'check': 'verdict is a confirmation', 'ok': record.get('verdict', '').startswith('confirmed')})
    promised = record.get('target_code_sha256')
    recomputed = None
    if promised and target:
        code = match.load_code(target, rpc or chains.endpoint(chain))
        recomputed = '0x' + __import__('hashlib').sha256(code).hexdigest()
        checks.append({'check': 'the target code still hashes to what the record pinned',
                       'ok': recomputed == promised, 'pinned': promised, 'now': recomputed})
    return {'kind': 'record', 'file': paths.display(path), 'placard': record.get('placard'), 'target': target,
            'verdict': record.get('verdict'), 'ok': all(c['ok'] for c in checks), 'checks': checks}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat verify')
    parser.add_argument('--sheet')
    parser.add_argument('--record')
    parser.add_argument('--expect', default=None, help='the digest a sheet must match')
    parser.add_argument('--rpc', default=None)
    parser.add_argument('--chain', default='mainnet', choices=sorted(chains.CHAINS))
    args = parser.parse_args(argv)
    if not (args.sheet or args.record):
        parser.error('pass --sheet or --record')
    out = []
    if args.sheet:
        out.append(verify_sheet(args.sheet, args.expect))
    if args.record:
        out.append(verify_record(args.record, args.rpc, args.chain))
    print(json.dumps(out if len(out) > 1 else out[0], indent=2, sort_keys=True))
    return 0 if all(item['ok'] for item in out) else 1


if __name__ == '__main__':
    sys.exit(main())
