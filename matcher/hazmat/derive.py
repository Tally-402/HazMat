"""Derive selectors from Solidity source and check them against live code.

Authoring a placard by hand-writing selectors is guessing. This derives the
signature list from source, expands struct parameters to their tuple form, and
optionally reports which selectors are actually present in the runtime code of a
deployed address. Only a selector that is present belongs in `require_all`.
"""
import argparse
import json
import re
import sys
from pathlib import Path

from . import keccak, match
EXTERNAL = re.compile(r'function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)')
STRUCT = re.compile(r'struct\s+(\w+)\s*\{([^}]*)\}')
NOISE = ('calldata', 'memory', 'storage', 'indexed', 'payable')


def structs(files):
    found = {}
    for path in files:
        text = Path(path).read_text()
        for name, body in STRUCT.findall(text):
            fields = []
            for line in body.split(';'):
                parts = [p for p in line.split() if p not in NOISE]
                if len(parts) >= 2:
                    fields.append(parts[0])
            if fields:
                found[name] = fields
    return found


def expand(value, table, depth=0):
    """Struct name to ABI tuple, recursively. Unknown names pass through."""
    if value in table and depth < 8:
        return '(' + ','.join(expand(f, table, depth + 1) for f in table[value]) + ')'
    return value


def signatures(paths):
    files = sorted(Path(p) for path in paths for p in
                   ([str(x) for x in Path(path).rglob('*.sol')] if Path(path).is_dir() else [path]))
    table = structs(files)
    out = {}
    for path in files:
        text = path.read_text()
        for name, args, rest in EXTERNAL.findall(text):
            if re.search(r'\b(internal|private)\b', rest):
                continue
            types = []
            for arg in args.split(','):
                arg = arg.strip()
                if not arg:
                    continue
                parts = [p for p in arg.split() if p not in NOISE]
                types.append(expand(parts[0], table))
            sig = '%s(%s)' % (name, ','.join(types))
            out[sig] = str(path)
    return out


def selector(signature):
    """Four-byte selector from the in-repo keccak, so cast is optional."""
    return keccak.selector(signature)


def run(paths, address=None, rpc=None):
    sigs = signatures(paths)
    constants = set()
    if address:
        code = match.load_code(address, rpc)
        constants = match.push4_constants(match.strip_metadata(code)[0])
    rows = []
    for sig in sorted(sigs):
        sel = selector(sig)
        rows.append({'signature': sig, 'selector': sel, 'source': sigs[sig],
                     'present': (sel[2:] in constants) if address and sel else None})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat derive')
    parser.add_argument('paths', nargs='+')
    parser.add_argument('--address')
    parser.add_argument('--rpc')
    parser.add_argument('--present-only', action='store_true')
    args = parser.parse_args(argv)
    rows = run(args.paths, args.address, args.rpc)
    if args.present_only and args.address:
        rows = [r for r in rows if r['present']]
    for row in rows:
        flag = '' if row['present'] is None else ('  PRESENT' if row['present'] else '  absent')
        print('%-58s %s%s' % (row['signature'], row['selector'], flag))
    if args.address:
        print('%d/%d present in %s' % (sum(1 for r in rows if r['present']), len(rows), args.address))
    return 0


if __name__ == '__main__':
    sys.exit(main())
