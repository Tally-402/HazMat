"""Match deployed bytecode against placards.

Two tiers, and the difference is honest: pattern claims are bytecode matches and
are only candidates; confirmed placards also ship an executed reproduction.
"""
import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import os
import time

from . import chains, resolve

DEFAULT_RPC = chains.CHAINS[chains.DEFAULT]['rpc']
# anchored to the repo, not the current directory: the register, the anchors and the
# name index all live beside the code and must resolve wherever a process starts
ROOT = Path(__file__).resolve().parents[2]


def rooted(path):
    path = Path(path)
    return path if path.is_absolute() else ROOT / path
MAX_METADATA = 0x1000


class MatchError(Exception):
    pass


def strip_metadata(code):
    """Split compiled code into body and CBOR metadata trailer.

    The trailer length is the last two bytes, big-endian. Metadata carries no
    executable behaviour and its hash varies with compiler build and source
    paths, so matching must exclude it.
    """
    if len(code) < 4:
        return code, b''
    size = int.from_bytes(code[-2:], 'big')
    if 0 < size <= MAX_METADATA and len(code) > size + 2:
        return code[:-size - 2], code[-size - 2:]
    return code, b''


def push4_constants(body):
    """Every four-byte constant pushed by PUSH4. Push data is skipped properly,
    otherwise bytes living inside a PUSH32 would look like a selector."""
    found = set()
    i = 0
    while i < len(body):
        op = body[i]
        if op == 0x63 and i + 4 < len(body):
            found.add(body[i + 1:i + 5].hex())
            i += 5
            continue
        i += 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
    return found


CACHE_DIR = ROOT / 'work' / 'cache'
CACHE_TTL = int(os.environ.get('HAZMAT_CACHE_TTL', '600'))


def cached_code(chain, address, rpc, ttl=None):
    """Read code with a short on-disk cache.

    A cached read means an upgrade is invisible for up to the ttl, which is the
    honest trade: say so rather than pretend freshness.
    """
    ttl = CACHE_TTL if ttl is None else ttl
    key = CACHE_DIR / ('code-%s-%s.json' % (chain, address.lower()))
    if ttl and key.is_file():
        try:
            row = json.loads(key.read_text())
            if time.time() - row['at'] < ttl:
                return bytes.fromhex(row['code'][2:]), True
        except (ValueError, KeyError, OSError):
            pass
    code = bytes.fromhex((resolve.code_hex(address, rpc) or '0x')[2:])
    if ttl:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            key.write_text(json.dumps({'at': time.time(), 'chain': chain, 'address': address.lower(),
                                       'code': '0x' + code.hex()}))
        except OSError:
            pass
    return code, False


def load_code(source, rpc=None, as_='auto', chain='mainnet', use_cache=True):
    """Read code from an address, raw hex, or a file.

    A 40-character hex string is ambiguous: it is exactly an address and also a
    plausible 20-byte code blob. `as_` settles it: 'auto' prefers the address and
    says so loudly when the chain has nothing there, 'code' reads it as bytecode.
    """
    if as_ not in ('auto', 'address', 'code'):
        raise MatchError('unknown as_: %s' % as_)
    if as_ == 'address' or (as_ == 'auto' and re.fullmatch(r'0x[0-9a-fA-F]{40}', source)):
        try:
            code, _ = (cached_code(chain, source, rpc or DEFAULT_RPC) if use_cache
                       else (bytes.fromhex((resolve.code_hex(source, rpc or DEFAULT_RPC) or '0x')[2:]), False))
        except resolve.ResolveError as exc:
            raise MatchError(str(exc))
        if not code:
            raise MatchError('no code at %s (an address with nothing deployed; pass as_/--as code to read it as bytecode)' % source)
        return code
    path = Path(source)
    if path.exists():
        return bytes.fromhex(path.read_text().strip().replace('0x', ''))
    if source.startswith('0x'):
        return bytes.fromhex(source[2:])
    raise MatchError('unrecognised source: %s' % source)


def load_register(directory):
    rows = [json.loads(p.read_text()) for p in sorted(Path(directory).glob('*.json'))]
    if not rows:
        raise MatchError('no placards in %s' % directory)
    return rows


FAMILIES = ('evm', 'solana', 'any')


def _bare(items):
    return [s.lower().replace('0x', '') for s in items]


def match_code(code, placards, family='evm'):
    """Match code against placards for one instruction set.

    A placard marked `any` is checked for every family. The assertion level is
    always `pattern`: a bytecode match is a candidate, never a confirmation.
    `require_none_of` is an absence check over the listed signatures only.
    """
    if family not in FAMILIES:
        raise MatchError('unknown family: %s' % family)
    body, trailer = strip_metadata(code)
    constants = push4_constants(body)
    results = []
    for placard in placards:
        if placard.get('chain_family', 'any') not in (family, 'any'):
            continue
        matcher = placard.get('matcher', {})
        if matcher.get('kind') != 'selector-set':
            continue
        required = _bare(matcher.get('require_all', []))
        any_of = _bare(matcher.get('require_any', []))
        none_of = _bare(matcher.get('require_none_of', []))
        if not (required or any_of):
            continue
        if not all(item in constants for item in required):
            continue
        if any_of and not any(item in constants for item in any_of):
            continue
        if none_of and any(item in constants for item in none_of):
            continue
        results.append({'id': placard['id'], 'title': placard['title'],
                        'placard_class': placard['placard_class'],
                        'placard_class_name': placard.get('placard_class_name'),
                        'tier': placard['tier'], 'assertion': 'pattern',
                        'matched_selectors': ['0x' + item for item in required + any_of],
                        'absent_checked': len(none_of),
                        'money_bound': placard.get('money_bound', {}),
                        'summary': placard.get('summary', ''),       # the prose a reader needs
                        'fix': placard.get('fix', ''),
                        'provenance': placard.get('provenance', {}),
                        'confirmed_on': placard.get('confirmed_on', [])})
    return results, {'code_bytes': len(code), 'body_bytes': len(body),
                     'metadata_bytes': len(trailer), 'push4_constants': len(constants)}


def latest_anchor(anchor_dir=None):
    anchor_dir = str(rooted(anchor_dir or 'anchors'))
    """The newest published epoch, so a sheet names the root it was matched against."""
    import json as _json
    paths = sorted(Path(anchor_dir).glob('epoch-*.json'), key=lambda p: int(p.stem.split('-')[1])) \
        if Path(anchor_dir).is_dir() else []
    if not paths:
        return None
    record = _json.loads(paths[-1].read_text())
    return {'epoch': record.get('epoch'), 'root': record.get('root'),
            'register_digest': record.get('register_digest'), 'file': paths[-1].name}


def load_selector_names(register_dir):
    path = rooted(Path(register_dir).parent) / 'selectors.json'
    if not path.is_file():
        return {}
    return json.loads(path.read_text()).get('selectors') or {}


def coverage(code, placards, register_dir):
    """What the register asked about, and what it did not.

    A clean sheet is the common case, so the sheet has to say what was actually
    read rather than only what matched.
    """
    body, _ = strip_metadata(code)
    constants = push4_constants(body)
    asked = set()
    for placard in placards:
        matcher = placard.get('matcher', {})
        for key in ('require_all', 'require_any', 'require_none_of'):
            asked |= set(_bare(matcher.get(key, [])))
    names = load_selector_names(register_dir)
    covered = sorted(c for c in constants if c in asked)
    uncovered = sorted(c for c in constants if c not in asked)
    return {
        'method': 'bytecode fingerprint only; no source or ABI required',
        'means': 'a match means the selectors a placard asks about are present. It does not mean reachable, and a clean sheet is not a clearance.',
        'placards_checked': len(placards),
        'classes_checked': sorted({p['placard_class'] for p in placards}),
        'selectors_in_code': len(constants),
        'selectors_the_register_asks_about': len(covered),
        'selectors_otherwise_unaccounted': len(uncovered),
        'covered': ['0x' + c for c in covered],
        'selectors_present': ['0x' + c for c in constants],      # everything the code exposes
        'unaccounted_sample': [{'selector': '0x' + c, 'signature': names.get(c)} for c in uncovered[:24]],
        'named_index_size': len(names),
    }


def register_digest(register_dir):
    """One digest over the whole register, so a sheet names the revision it used."""
    rows = sorted(Path(register_dir).glob('*.json'))
    blob = b''.join(p.read_bytes() for p in rows)
    return '0x' + hashlib.sha256(blob).hexdigest()[:16]


def scan_target(address, placards, register_dir, rpc, family, chain, use_cache=True):
    code = load_code(address, rpc, 'address', chain, use_cache)
    found, stats = match_code(code, placards, family)
    return {'at': address.lower(), 'stats': stats, 'matches': found,
            'coverage': coverage(code, placards, register_dir),
            'code_sha256': '0x' + hashlib.sha256(code).hexdigest(),
            'identity': resolve.identity(address, rpc, chains.chain_id(chain))}


def scan(source, register_dir, rpc=None, family='evm', as_='auto', chain='mainnet', use_cache=True):
    rpc = rpc or chains.endpoint(chain)
    placards = load_register(register_dir)
    is_address = bool(re.fullmatch(r'0x[0-9a-fA-F]{40}', source)) and as_ != 'code'
    subject = None
    scans = []
    if is_address:
        # what is this, and where does the logic live? scanning a wrapper and
        # reporting no match would be confident and wrong
        resolved = resolve.resolve(source, rpc, chain)
        subject = {k: resolved[k] for k in ('requested', 'chain', 'kind', 'effective', 'via', 'evidence')}
        subject['targets'] = [{'address': a, 'role': r} for a, r in resolved['targets']]
        for address, role in resolved['targets']:
            try:
                row = scan_target(address, placards, register_dir, rpc, family, chain, use_cache)
            except MatchError as exc:
                scans.append({'at': address.lower(), 'role': role, 'state': 'blocked', 'error': str(exc),
                              'matches': [], 'stats': {}, 'coverage': {}})
                continue
            row['role'] = role
            scans.append(row)
        subject['identity'] = {s['at']: s['identity'] for s in scans if s.get('identity')}
    else:
        code = load_code(source, rpc, as_, chain, use_cache)
        found, stats = match_code(code, placards, family)
        scans.append({'at': source, 'role': 'code', 'stats': stats, 'matches': found,
                      'coverage': coverage(code, placards, register_dir),
                      'code_sha256': '0x' + hashlib.sha256(code).hexdigest()})
    headline = next((s for s in scans if s.get('role') in ('implementation', 'delegate', 'clone target')), scans[0])
    merged = []
    for row in scans:
        for found in row['matches']:
            merged.append(dict(found, at=row['at'], role=row['role']))
    return {'target': source, 'family': family, 'subject': subject, 'scans': scans,
            'coverage': headline.get('coverage', {}),
            'register_anchor': latest_anchor(),
            'code_sha256': headline.get('code_sha256'),
            'register_size': len(placards), 'stats': headline.get('stats', {}), 'matches': merged,
            'assertion': 'pattern match only; confirmation runs are separate',
            'register_digest': register_digest(register_dir),
    'not_checked': ['resolution is best effort: unknown proxy patterns, diamond facets and '
                    'beacons pointing at beacons are labelled not followed',
                    'reachability', 'economic preconditions',
                            'state at any particular block', 'source-level reasoning',
                            'anything not covered by a placard']}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat match')
    parser.add_argument('--register', default='register/placards')
    parser.add_argument('--code', required=True, help='0x-hex, a file, or a contract address')
    parser.add_argument('--rpc', default=None)
    parser.add_argument('--chain', default=None, choices=sorted(chains.CHAINS))
    parser.add_argument('--family', default='evm', choices=list(FAMILIES))
    parser.add_argument('--as', dest='as_', default='auto', choices=['auto', 'address', 'code'],
                        help='how to read --code: an address, raw bytecode, or guess')
    parser.add_argument('--pdf', dest='pdf_out', default=None, help='also write the sheet as a PDF')
    parser.add_argument('--sheet', dest='sheet_out', default=None, help='also write the sheet as HTML')
    args = parser.parse_args(argv)
    if args.chain:
        args.rpc = chains.endpoint(args.chain)
    try:
        report = scan(args.code, args.register, args.rpc, args.family, args.as_)
        if args.pdf_out or args.sheet_out:
            from . import pdf as pdfmod
            from . import sds as sdsmod
            page, digest = sdsmod.render(report)
            if args.sheet_out:
                Path(args.sheet_out).write_text(page)
                report['sheet'] = args.sheet_out
            if args.pdf_out:
                Path(args.pdf_out).write_bytes(pdfmod.render_pdf(report))
                report['pdf'] = args.pdf_out
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except MatchError as exc:
        print(json.dumps({'state': 'blocked', 'error': str(exc)}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
