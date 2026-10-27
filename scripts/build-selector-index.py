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

from hazmat import confirm, derive                              # noqa: E402

INDEX = ROOT / 'register' / 'selectors.json'


# names for the standard surface every reader already knows: an "unaccounted" list that
# says 0x70a08231 instead of balanceOf(address) is noise
STANDARD = """
name() symbol() decimals() totalSupply() balanceOf(address) transfer(address,uint256)
transferFrom(address,address,uint256) approve(address,uint256) allowance(address,address)
owner() transferOwnership(address) renounceOwnership() acceptOwnership() pendingOwner() isOwner()
paused() pause() unpause()
ownerOf(uint256) tokenURI(uint256) safeTransferFrom(address,address,uint256)
safeTransferFrom(address,address,uint256,bytes) setApprovalForAll(address,bool)
isApprovedForAll(address,address) tokenByIndex(uint256) tokenOfOwnerByIndex(address,uint256)
balanceOf(address,uint256) safeBatchTransferFrom(address,address,uint256[],uint256[],bytes) uri(uint256)
supportsInterface(bytes4) isValidSignature(bytes32,bytes)
permit(address,address,uint256,uint256,uint8,bytes32,bytes32) nonces(address) DOMAIN_SEPARATOR()
granularity() defaultOperators() isOperatorFor(address,address) authorizeOperator(address)
revokeOperator(address) send(address,uint256,bytes) operatorSend(address,address,uint256,bytes,bytes)
operatorBurn(address,uint256,bytes,bytes) tokensReceived(address,address,address,uint256,bytes,bytes)
tokensToSend(address,address,address,uint256,bytes,bytes) canImplementInterfaceForAddress(bytes32,address)
Error(string) Panic(uint256) isValidSignature(bytes,bytes)
getInterfaceImplementer(address,bytes32) setInterfaceImplementer(address,bytes32,address)
getManager(address) setManager(address,address)
deposit() withdraw(uint256) totalAssets() totalSupply()
""".split()


def main():
    # merged into what is already there, not replaced: a name should not disappear just
    # because a work directory was cleaned, and this index claims nothing about the code
    existing = json.loads(INDEX.read_text()) if INDEX.is_file() else {'selectors': {}}
    out = {'note': existing.get('note', 'comfort reading for the uncovered list: selector to signature. A convenience index, not verification; a name here is keccak(signature) and nothing more.'),
           'count': 0, 'selectors': dict(existing.get('selectors') or {})}
    standard = len(STANDARD)
    for signature in STANDARD:
        out['selectors'].setdefault(derive.selector(signature)[2:], signature)
    collisions, missing = [], []
    # every local work tree, not only the ones a record names: the register's other targets
    # (a proxy's implementation, a pattern placard that was never confirmed) have trees too
    trees = sorted((ROOT / 'work').glob('*/src')) if (ROOT / 'work').is_dir() else []
    # plus whatever source roots an unconfirmed target's code was authored in, which the
    # confirmation records for pattern placards never fetched
    for candidate in confirm.SOURCE_ROOT_CANDIDATES:
        path = Path(candidate)
        if path.is_dir():
            trees.append(path)
            for lib in sorted(path.parent.glob('lib/*/src')) + sorted(path.parent.glob('lib/*/contracts')):
                trees.append(lib)               # vendored libraries name most of the rest
    for record in sorted((ROOT / 'confirmations').glob('HZ-*.json')):
        rec = json.loads(record.read_text())
        workdir = ROOT / str(rec.get('workdir') or '')
        trees.append(workdir / 'src')
    for tree in trees:
        sources = sorted(tree.rglob('*.sol')) if tree.is_dir() else []
        if not sources:
            missing.append(str(tree.parent.name if tree.parent else tree))
            continue
        for signature in derive.signatures([str(p) for p in sources]):
            selector = derive.selector(signature)[2:]
            known = out['selectors'].get(selector)
            if known and known != signature:
                collisions.append((selector, known, signature))
            out['selectors'][selector] = signature
    out['count'] = len(out['selectors'])
    INDEX.write_text(json.dumps(dict(sorted(out.items())), indent=1, sort_keys=True) + '\n')
    print('%d selectors from %d source trees' % (out['count'], len(trees) - len(missing)))
    if missing:
        print('  no local sources for: %s' % ', '.join(missing))
    if collisions:
        print('  selector collisions: %s' % collisions)
    return 0


if __name__ == '__main__':
    sys.exit(main())
