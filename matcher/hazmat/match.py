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

DEFAULT_RPC = 'https://ethereum-rpc.publicnode.com'
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


def load_code(source, rpc=None):
    if re.fullmatch(r'0x[0-9a-fA-F]{40}', source):
        payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getCode',
                              'params': [source, 'latest']}).encode()
        request = urllib.request.Request(rpc or DEFAULT_RPC, data=payload,
                                         headers={'content-type': 'application/json',
                                                  'user-agent': 'hazmat/0.1'})
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                body = json.loads(response.read())
        except urllib.error.URLError as exc:
            raise MatchError('rpc unreachable: %s' % exc)
        if 'result' not in body:
            raise MatchError('rpc error: %s' % body.get('error'))
        raw = body['result']
        if raw in ('0x', '0x0'):
            raise MatchError('no code at %s' % source)
        return bytes.fromhex(raw[2:])
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


def match_code(code, placards):
    body, trailer = strip_metadata(code)
    constants = push4_constants(body)
    results = []
    for placard in placards:
        matcher = placard.get('matcher', {})
        if matcher.get('kind') != 'selector-set':
            continue
        required = [s.lower().replace('0x', '') for s in matcher.get('require_all', [])]
        if not required:
            continue
        if all(item in constants for item in required):
            results.append({'id': placard['id'], 'title': placard['title'],
                            'placard_class': placard['placard_class'],
                            'placard_class_name': placard.get('placard_class_name'),
                            'tier': placard['tier'], 'assertion': 'pattern',
                            'matched_selectors': ['0x' + item for item in required],
                            'money_bound': placard.get('money_bound', {}),
                            'confirmed_on': placard.get('confirmed_on', [])})
    return results, {'code_bytes': len(code), 'body_bytes': len(body),
                     'metadata_bytes': len(trailer), 'push4_constants': len(constants)}


def scan(source, register_dir, rpc=None):
    code = load_code(source, rpc)
    placards = load_register(register_dir)
    matches, stats = match_code(code, placards)
    return {'target': source, 'code_sha256': '0x' + hashlib.sha256(code).hexdigest(),
            'register_size': len(placards), 'stats': stats, 'matches': matches,
            'assertion': 'pattern match only; confirmation runs are separate',
            'not_checked': ['reachability', 'economic preconditions',
                            'state at any particular block', 'source-level reasoning',
                            'anything not covered by a placard']}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat match')
    parser.add_argument('--register', default='register/placards')
    parser.add_argument('--code', required=True, help='0x-hex, a file, or a contract address')
    parser.add_argument('--rpc', default=None)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(scan(args.code, args.register, args.rpc), indent=2, sort_keys=True))
        return 0
    except MatchError as exc:
        print(json.dumps({'state': 'blocked', 'error': str(exc)}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
