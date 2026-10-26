"""Work out what to actually scan.

Most addresses users paste are not the thing holding the logic: EOAs delegated
by EIP-7702 are a 23-byte pointer, minimal clones are 45 bytes, and proxies hold
a wrapper while the code lives behind an implementation pointer. Scanning the
wrapper and reporting "no match" is a confident, wrong answer, so this resolves
first and reports both addresses.

Best effort by construction: there are proxy patterns this does not know, so an
unresolved shape is labelled rather than silently treated as final.
"""
import json
import re
import urllib.error
import urllib.request

# standard implementation slots, all keccak-derived names
SLOTS = (
    ('eip1967 implementation', '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'),
    ('eip1967 beacon', '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'),
    ('eip1822 proxiable', '0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7'),
    ('oz legacy implementation', '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3'),
)
IMPLEMENTATION_SELECTOR = '0x5c60da1b'      # implementation()
MINIMAL_CLONE = re.compile(r'^0x363d3d373d3d3d363d73([0-9a-fA-F]{40})5af43d82803e903d91602b57fd5bf3$')
DELEGATED_EOA = re.compile(r'^0xef0100([0-9a-fA-F]{40})$')
DELEGATE = 0xf4                              # DELEGATECALL opcode
MAX_HOPS = 3
ZERO = '0x' + '0' * 40


class ResolveError(Exception):
    pass


def rpc_call(rpc, method, params, timeout=45):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    request = urllib.request.Request(rpc, data=body, headers={'content-type': 'application/json',
                                                              'user-agent': 'hazmat/0.1'})
    try:
        reply = json.loads(urllib.request.urlopen(request, timeout=timeout).read())
    except urllib.error.URLError as exc:
        raise ResolveError('rpc unreachable: %s' % exc)
    if 'result' not in reply:
        raise ResolveError('rpc error: %s' % reply.get('error'))
    return reply['result']


def code_hex(address, rpc):
    return rpc_call(rpc, 'eth_getCode', [address, 'latest']) or '0x'


def read_slot(address, slot, rpc):
    value = rpc_call(rpc, 'eth_getStorageAt', [address, slot, 'latest']) or '0x0'
    return int(value, 16) if value.startswith('0x') else 0


def call_for_address(address, selector, rpc):
    """Call a zero-argument getter and read an address out of the word."""
    try:
        out = rpc_call(rpc, 'eth_call', [{'to': address, 'data': selector}, 'latest'])
    except ResolveError:
        return None
    if not out or out == '0x' or len(out) < 42:
        return None
    word = out[-40:]
    candidate = '0x' + word
    return None if int(word, 16) == 0 else candidate


def _has_code(address, rpc):
    code = code_hex(address, rpc)
    return code not in ('0x', '0x0', '')


def resolve(address, rpc, chain='mainnet', hops=0, seen=None):
    """Return what this address is and where the logic actually lives.

    `targets` is what should be scanned, requested first. `kind` is deliberately
    conservative: `possible-proxy` means the code delegatecalls but no pointer was
    found, which is a hedge and not a resolution.
    """
    seen = seen or set()
    address = address.lower()
    code = code_hex(address, rpc)
    out = {'requested': address, 'chain': chain, 'kind': 'contract', 'effective': address,
           'via': None, 'targets': [(address, 'requested')], 'evidence': [], 'hops': hops}
    if code in ('0x', '0x0', ''):
        out.update(kind='no-code', effective=None, targets=[(address, 'requested')])
        out['evidence'].append('eth_getCode returned nothing: an EOA, a precompile, or not yet deployed')
        return out

    delegated = DELEGATED_EOA.match(code)
    if delegated:
        # EIP-7702: a 23-byte pointer to the account's code
        target = '0x' + delegated.group(1).lower()   # the group drops the prefix; keep addresses uniform
        out.update(kind='delegated-eoa', effective=target, via='EIP-7702 designator',
                   targets=[(address, 'requested'), (target, 'delegate')])
        out['evidence'].append('code is 0xef0100 plus an address, %d bytes in total' % ((len(code) - 2) // 2))
        if target not in seen:
            seen.add(target)
            out['delegate_of_delegate'] = resolve(target, rpc, chain, hops + 1, seen) if hops < MAX_HOPS else None
        return out

    clone = MINIMAL_CLONE.match(code)
    if clone:
        target = '0x' + clone.group(1).lower()
        out.update(kind='minimal-clone', effective=target, via='EIP-1167 minimal proxy bytecode',
                   targets=[(address, 'requested'), (target, 'clone target')])
        out['evidence'].append('code is the 45-byte canonical clone, %d bytes' % ((len(code) - 2) // 2))
        return out

    if hops < MAX_HOPS:
        for name, slot in SLOTS:
            stored = read_slot(address, slot, rpc)
            if not stored:
                continue
            target = '0x' + ('%040x' % stored)[-40:]
            if target == ZERO or target == address or target in seen:
                continue
            if name.endswith('beacon'):
                behind = call_for_address(target, IMPLEMENTATION_SELECTOR, rpc)
                out['evidence'].append('%s holds %s; that beacon reports implementation %s'
                                       % (name, target, behind))
                target = behind or target
            else:
                out['evidence'].append('%s slot holds %s' % (name, target))
            if target and target != ZERO:
                out.update(kind='proxy', effective=target, via=name,
                           targets=[(address, 'requested'), (target, 'implementation')])
                if _has_code(target, rpc):
                    return out
                out['evidence'].append('implementation %s has no code' % target)
                out.update(kind='proxy-dangling')
                return out
        # not a standard slot: ask the contract, which is how bespoke proxies publish it
        target = call_for_address(address, IMPLEMENTATION_SELECTOR, rpc)
        if target and target != address:
            out['evidence'].append('implementation() returned %s' % target)
            if _has_code(target, rpc):
                out.update(kind='proxy', effective=target, via='implementation() getter',
                           targets=[(address, 'requested'), (target, 'implementation')])
                return out
    if DELEGATE in bytes.fromhex(code[2:]) and len(code) < 8192:
        out.update(kind='possible-proxy')
        out['evidence'].append('code contains delegatecall and no standard pointer was found; '
                               'the logic may live somewhere this resolver cannot see')
    return out


def identity(address, rpc, chain_id=1, base='https://sourcify.dev/server/v2/contract/%s/%s?fields=compilation'):
    """Who the address says it is, on Sourcify. Failure is fine and reported."""
    url = base % (chain_id, address)
    request = urllib.request.Request(url, headers={'user-agent': 'hazmat/0.1'})
    try:
        record = json.loads(urllib.request.urlopen(request, timeout=60).read())
    except urllib.error.HTTPError as exc:
        return {'state': 'not-found' if exc.code == 404 else 'error', 'http': exc.code}
    except urllib.error.URLError as exc:
        return {'state': 'unreachable', 'error': str(exc)}
    compilation = record.get('compilation') or {}
    return {'state': 'verified', 'name': compilation.get('name'),
            'compiler': compilation.get('compilerVersion'),
            'verified_at': record.get('verifiedAt'), 'match': record.get('match')}
