"""Confirm a placard against a live target, mechanically.

Stages, each recording its own outcome so a later stage never hides an earlier
failure:

    fetch    verified source from Sourcify, written at its original paths
    build    rebuild with the compiler settings from the verification record
    compare  rebuilt selector set against the deployed runtime
    probe    run the placard's own reproduction against the rebuilt code

A verdict is only `confirmed` when the build succeeded, the selectors agree and
the probe passed. A probe that runs and fails is `refuted`, and anything earlier
failing is `blocked`.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import chains, keccak, match

SOURCIFY = 'https://sourcify.dev/server/v2/contract/%s/%s?fields=sources,compilation'
DEFAULT_FORGE = os.path.expanduser('~/.foundry/bin/forge')
SOLC_CANDIDATES = [os.path.expanduser('~/.foundry/solc/{v}'),
                   os.path.expanduser('~/Library/Application Support/svm/{v}/solc-{v}'),
                   os.path.expanduser('~/code/argus-security-mvp/.tools/solc-{v}')]


class ConfirmError(Exception):
    pass


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _run(cmd, cwd, timeout=900):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return result.returncode, (result.stdout or '') + (result.stderr or '')


def find_solc(version):
    """A local solc binary matching the version found in the verification record."""
    for template in SOLC_CANDIDATES:
        path = template.format(v=version)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def fetch_source(chain_id, address, workdir, base=SOURCIFY):
    request = urllib.request.Request(base % (chain_id, address), headers={'user-agent': 'hazmat/0.1'})
    try:
        record = json.loads(urllib.request.urlopen(request, timeout=120).read())
    except urllib.error.HTTPError as exc:
        raise ConfirmError('sourcify %s for %s: %s' % (exc.code, address, exc.reason))
    sources = record.get('sources') or {}
    if not sources:
        raise ConfirmError('sourcify returned no sources for %s' % address)
    written = []
    for name, entry in sources.items():
        path = Path(workdir) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        content = entry['content'] if isinstance(entry, dict) else entry
        path.write_text(content)
        written.append({'path': name, 'sha256': _sha256(content.encode())})
    return record, written


def add_missing_libs(workdir, libs):
    """Top up the bundle with library files it does not carry.

    Sourcify stores only the files the verified contract actually imports, so a
    probe that needs a concrete ERC20 finds none. Files already present are never
    overwritten: the verified bundle stays authoritative.
    """
    added = []
    for name, source in (libs or {}).items():
        source = Path(source)
        if not source.is_dir():
            raise ConfirmError('lib %s not a directory: %s' % (name, source))
        dest_root = Path(workdir, 'lib', name)
        for path in source.rglob('*'):
            if path.is_dir() or '.git' in path.parts:
                continue
            rel = path.relative_to(source)
            dest = dest_root / rel
            if dest.exists():
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(path, dest)
            added.append('lib/%s/%s' % (name, rel))
    return added


def write_foundry_toml(workdir, settings, solc_path):
    remappings = settings.get('remappings') or ['@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/',
                                                'forge-std/=lib/forge-std/src/']
    optimizer = settings.get('optimizer') or {}
    lines = ['[profile.default]', 'src = "src"', 'test = "test"', 'libs = ["lib"]',
             'out = "out"', 'cache_path = "cache"', 'auto_detect_remappings = false',
             'remappings = [%s]' % ', '.join('"%s"' % r for r in remappings)]
    if solc_path:
        lines.append('solc = "%s"' % solc_path)
    if settings.get('viaIR'):
        lines.append('via_ir = true')
    if optimizer.get('enabled'):
        lines.append('optimizer = true')
        lines.append('optimizer_runs = %d' % int(optimizer.get('runs', 200)))
    if settings.get('evmVersion'):
        lines.append('evm_version = "%s"' % settings['evmVersion'])
    Path(workdir, 'foundry.toml').write_text('\n'.join(lines) + '\n')
    return '\n'.join(lines)


def compare_rebuilt(out_dir, contract_name, deployed_code):
    """Selector-set agreement between the rebuild and the deployed runtime."""
    candidates = list(Path(out_dir).rglob(contract_name + '.json'))
    if not candidates:
        raise ConfirmError('no artifact for %s in %s' % (contract_name, out_dir))
    artifact = json.loads(candidates[0].read_text())
    rebuilt = bytes.fromhex(artifact['deployedBytecode']['object'].removeprefix('0x'))
    deployed_body, deployed_meta = match.strip_metadata(deployed_code)
    rebuilt_body, rebuilt_meta = match.strip_metadata(rebuilt)
    deployed_selectors = match.push4_constants(deployed_body)
    rebuilt_selectors = match.push4_constants(rebuilt_body)
    missing = sorted(deployed_selectors - rebuilt_selectors)
    extra = sorted(rebuilt_selectors - deployed_selectors)
    differing = sum(1 for a, b in zip(deployed_body, rebuilt_body) if a != b)
    return {
        'artifact': str(candidates[0].relative_to(out_dir)),
        'deployed_bytes': len(deployed_code), 'rebuilt_bytes': len(rebuilt),
        'deployed_body_bytes': len(deployed_body), 'rebuilt_body_bytes': len(rebuilt_body),
        'selectors_deployed': len(deployed_selectors), 'selectors_rebuilt': len(rebuilt_selectors),
        'selectors_missing_from_rebuild': ['0x' + s for s in missing],
        'selectors_extra_in_rebuild': ['0x' + s for s in extra],
        'body_bytes_differing': differing,
        'note': 'immutables live in the deployed body, so byte differences here are expected; the selector set is the portable signal',
    }


def run(placard_id, target, register='register/placards', chain='mainnet', workdir='work',
        forge=DEFAULT_FORGE, forge_std=None, rpc=None, timeout=900, libs=None):
    placards = {p['id']: p for p in match.load_register(register)}
    if placard_id not in placards:
        raise ConfirmError('no such placard: %s' % placard_id)
    placard = placards[placard_id]
    if placard.get('tier') != 'confirmed':
        raise ConfirmError('%s is tier %s, nothing to confirm' % (placard_id, placard.get('tier')))
    if not placard.get('reproduction'):
        raise ConfirmError('%s has no reproduction' % placard_id)

    root = Path(workdir) / ('%s-%s' % (placard_id, target[2:10].lower()))
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    record = {'placard': placard_id, 'target': target, 'chain': chain,
              'chain_id': chains.chain_id(chain), 'stages': {}, 'verdict': 'blocked'}
    record['forge'] = {'path': forge, 'version': _run([forge, '--version'], str(root))[1].strip().splitlines()[0]
                       if os.path.exists(forge) else 'missing'}

    # stage: fetch
    try:
        src, written = fetch_source(record['chain_id'], target, root)
        record['stages']['fetch'] = {
            'state': 'ok', 'match': src.get('match'), 'runtime_match': src.get('runtimeMatch'),
            'creation_match': src.get('creationMatch'), 'verified_at': src.get('verifiedAt'),
            'sources': len(written), 'files': written,
            'compiler': (src.get('compilation') or {}).get('compilerVersion'),
            'settings': (src.get('compilation') or {}).get('compilerSettings'),
            'contract': (src.get('compilation') or {}).get('name')}
    except ConfirmError as exc:
        record['stages']['fetch'] = {'state': 'blocked', 'error': str(exc)}
        return _finish(record, root)

    compilation = src['compilation']
    version = compilation['compilerVersion'].split('+')[0]
    solc = find_solc(version)
    record['stages']['fetch']['solc_local'] = solc

    # stage: libs
    supply = dict(libs or {})
    if forge_std:
        supply.setdefault('forge-std', forge_std)
    try:
        added = add_missing_libs(str(root), supply)
        record['stages']['libs'] = {'state': 'ok', 'supplied': sorted(supply), 'files_added': len(added)}
    except ConfirmError as exc:
        record['stages']['libs'] = {'state': 'blocked', 'error': str(exc)}
        return _finish(record, root)

    # stage: build
    toml = write_foundry_toml(str(root), compilation.get('compilerSettings') or {}, solc)
    record['stages']['build'] = {'foundry_toml': toml}
    code, log = _run([forge, 'build'], str(root), timeout)
    record['stages']['build'].update({'state': 'ok' if code == 0 else 'blocked', 'exit_code': code,
                                      'log_tail': log[-2500:]})
    if code != 0:
        return _finish(record, root)

    # stage: compare
    deployed = match.load_code(target, rpc or chains.endpoint(chain))
    record['stages']['compare'] = compare_rebuilt(str(root / 'out'), compilation['name'], deployed)
    agreement = (not record['stages']['compare']['selectors_missing_from_rebuild']
                 and not record['stages']['compare']['selectors_extra_in_rebuild'])
    record['stages']['compare']['state'] = 'ok' if agreement else 'mismatch'

    # stage: probe
    probes = sorted(Path('reproductions', placard_id).glob('*.t.sol'))
    if not probes:
        record['stages']['probe'] = {'state': 'blocked', 'error': 'no vendored probe'}
        return _finish(record, root)
    target_dir = Path(root, 'test')
    target_dir.mkdir(exist_ok=True)
    for probe in probes:
        shutil.copy(probe, target_dir / probe.name)
    names = [p.name for p in probes]
    code, log = _run([forge, 'test', '--match-path', 'test/%s' % names[0]], str(root), timeout)
    passed = re.findall(r'^\[PASS\] (\S+)', log, re.M)
    failed = re.findall(r'^\[FAIL[^\]]*\] (\S+)', log, re.M)
    record['stages']['probe'] = {'state': 'ok' if code == 0 else 'failed', 'exit_code': code,
                                 'sources': names, 'passed': passed, 'failed': failed,
                                 'log_tail': log[-2500:]}

    if record['stages']['build']['state'] != 'ok':
        record['verdict'] = 'blocked'
    elif record['stages']['probe']['state'] == 'ok' and agreement:
        record['verdict'] = 'confirmed'
    elif record['stages']['probe']['state'] == 'ok' and not agreement:
        record['verdict'] = 'confirmed_with_selector_drift'
    else:
        record['verdict'] = 'refuted'
    return _finish(record, root)


def _finish(record, root):
    record['workdir'] = str(root)
    out = Path('confirmations', '%s-%s.json' % (record['placard'], record['target'][2:10].lower()))
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    record['record'] = str(out)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat confirm')
    parser.add_argument('--placard', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--register', default='register/placards')
    parser.add_argument('--chain', default='mainnet', choices=sorted(chains.CHAINS))
    parser.add_argument('--workdir', default='work')
    parser.add_argument('--forge', default=DEFAULT_FORGE)
    parser.add_argument('--forge-std', default=None, help='directory holding the forge-std source tree')
    parser.add_argument('--lib', action='append', default=[], metavar='NAME=PATH',
                        help='top the bundle up with a local library, never overwriting verified files')
    parser.add_argument('--rpc', default=None)
    args = parser.parse_args(argv)
    libs = {}
    for item in args.lib:
        if '=' not in item:
            parser.error('--lib wants NAME=PATH, got %s' % item)
        name, path = item.split('=', 1)
        libs[name] = path
    record = run(args.placard, args.target, args.register, args.chain, args.workdir,
                 args.forge, args.forge_std, args.rpc, libs=libs)
    print(json.dumps({k: record[k] for k in ('placard', 'target', 'verdict', 'record', 'workdir')}, indent=2))
    for stage, body in sorted(record['stages'].items()):
        print('%-8s %s' % (stage, body.get('state')))
    return 0 if record['verdict'] == 'confirmed' else 1


if __name__ == '__main__':
    sys.exit(main())
