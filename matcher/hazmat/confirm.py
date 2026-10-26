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

from . import chains, match

SOURCIFY = 'https://sourcify.dev/server/v2/contract/%s/%s?fields=sources,compilation'
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FORGE = os.path.expanduser('~/.foundry/bin/forge')
DEFAULT_REGISTER = str(ROOT / 'register' / 'placards')
# Libraries and upstream sources a probe may need, discovered rather than demanded.
# An entry can be overridden with HAZMAT_LIBS="name=/path:name2=/path2" or --lib.
LIB_CANDIDATES = {
    'forge-std': [os.path.expanduser('~/code/claus-network-specimen/contracts/lib/forge-std'),
                  'lib/forge-std'],
    'openzeppelin-contracts': [os.path.expanduser('~/code/claus-network-specimen/contracts/lib/openzeppelin-contracts'),
                               'lib/openzeppelin-contracts'],
}
SOURCE_ROOT_CANDIDATES = [os.path.expanduser('~/code/claus-network-specimen/contracts/src')]


def discover_libs(explicit=None):
    """Nothing should be mandatory: find what exists, record what was used."""
    found = dict(explicit or {})
    for pair in filter(None, (os.environ.get('HAZMAT_LIBS') or '').split(':')):
        if '=' in pair:
            name, path = pair.split('=', 1)
            found.setdefault(name, path)
    for name, candidates in LIB_CANDIDATES.items():
        if name in found:
            continue
        for candidate in candidates:
            if os.path.isdir(candidate):
                found[name] = candidate
                break
    return found


def discover_source_root(explicit=None):
    if explicit:
        return explicit
    for candidate in SOURCE_ROOT_CANDIDATES:
        if os.path.isdir(candidate):
            return candidate
    return None


def normalise_target(value, placard=None):
    """A target may be a bare address or a label with the address inside it."""
    if value:
        found = re.search(r'0x[0-9a-fA-F]{40}', value)
        if found:
            return found.group(0)
        raise ConfirmError('no address in target %r' % value)
    for entry in placard.get('confirmed_on') or []:
        found = re.search(r'0x[0-9a-fA-F]{40}', entry.get('target', ''))
        if found:
            return found.group(0)
    raise ConfirmError('%s declares no target; pass --target' % placard['id'])
SOLC_CANDIDATES = [os.path.expanduser('~/.foundry/solc/{v}'),
                   os.path.expanduser('~/Library/Application Support/svm/{v}/solc-{v}'),
                   os.path.expanduser('~/code/argus-security-mvp/.tools/solc-{v}')]


class ConfirmError(Exception):
    pass


def _sha256(data):
    if isinstance(data, str):
        data = data.encode()
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


def fetch_source(chain_id, address, workdir, base=SOURCIFY, fallback_chains=(1,)):
    """Fetch a verified source. Extras may live on another chain, so fall back."""
    record, used, last = None, chain_id, None
    for candidate in [chain_id] + [c for c in fallback_chains if c != chain_id]:
        request = urllib.request.Request(base % (candidate, address), headers={'user-agent': 'hazmat/0.1'})
        try:
            record = json.loads(urllib.request.urlopen(request, timeout=120).read())
            used = candidate
            break
        except urllib.error.HTTPError as exc:
            last = 'sourcify %s on chain %s for %s: %s' % (exc.code, candidate, address, exc.reason)
    if record is None:
        raise ConfirmError(last or 'no record for %s' % address)
    record['_fetched_on_chain'] = used
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


def add_sources(workdir, pairs):
    """Supplement files the verified bundle does not carry.

    Sourcify stores only what the verified contract imports, so a probe that
    touches a sibling contract (or its undeployed twin) has nothing to compile
    against. A file already present is never overwritten: the bundle wins.
    """
    added = []
    for rel, path in pairs:
        dest = Path(workdir, rel)
        if dest.exists():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        content = Path(path).read_bytes()
        dest.write_bytes(content)
        added.append({'path': rel, 'source': path, 'sha256': _sha256(content)})
    return added


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


NEEDED_REMAPPINGS = ['@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/',
                     'forge-std/=lib/forge-std/src/']


def write_foundry_toml(workdir, settings, solc_path=None, solc_version=None):
    """The record's remappings are authoritative, but they are often partial.

    A verified contract that never imports forge-std has no remapping for it, and
    `auto_detect_remappings = false` means the test files then cannot find it. Any
    needed remapping the record omits is appended, never substituted.
    """
    remappings = list(settings.get('remappings') or [])
    for needed in NEEDED_REMAPPINGS:
        if not any(r.split('=')[0] == needed.split('=')[0] for r in remappings):
            remappings.append(needed)
    optimizer = settings.get('optimizer') or {}
    lines = ['[profile.default]', 'src = "src"', 'test = "test"', 'libs = ["lib"]',
             'out = "out"', 'cache_path = "cache"', 'auto_detect_remappings = false',
             'remappings = [%s]' % ', '.join('"%s"' % r for r in remappings)]
    if solc_path:
        lines.append('solc = "%s"' % solc_path)
    elif solc_version:
        lines.append('solc_version = "%s"' % solc_version)
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
    common = min(len(deployed_body), len(rebuilt_body))
    differing = sum(1 for i in range(common) if deployed_body[i] != rebuilt_body[i])
    return {
        'artifact': str(candidates[0].relative_to(out_dir)),
        'deployed_bytes': len(deployed_code), 'rebuilt_bytes': len(rebuilt),
        'deployed_body_bytes': len(deployed_body), 'rebuilt_body_bytes': len(rebuilt_body),
        'selectors_deployed': len(deployed_selectors), 'selectors_rebuilt': len(rebuilt_selectors),
        'selectors_missing_from_rebuild': ['0x' + s for s in missing],
        'selectors_extra_in_rebuild': ['0x' + s for s in extra],
        'body_bytes_differing': differing,
        'body_length_delta': len(rebuilt_body) - len(deployed_body),
        'note': 'immutables live in the deployed body, so byte differences here are expected; the selector set is the portable signal',
    }


def run(placard_id, target, register='register/placards', chain='mainnet', workdir='work',
        forge=DEFAULT_FORGE, forge_std=None, rpc=None, timeout=900, libs=None, sources=None,
        add=None, source_root=None):
    placards = {p['id']: p for p in match.load_register(register)}
    if placard_id not in placards:
        raise ConfirmError('no such placard: %s' % placard_id)
    placard = placards[placard_id]
    target = normalise_target(target, placard)
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
    if not os.path.exists(forge):
        record['stages']['build'] = {'state': 'blocked', 'error': 'no forge at %s' % forge}
        record['forge'] = {'path': forge, 'version': 'missing'}
        return _finish(record, root)
    record['forge'] = {'path': forge, 'version': _run([forge, '--version'], str(root))[1].strip().splitlines()[0]}

    # stage: fetch (the target, plus any extra verified sources the probe needs)
    wanted = [target] + [s for s in (sources or []) if s.lower() != target.lower()]
    fetches, src = [], None
    try:
        for address in wanted:
            body, written = fetch_source(record['chain_id'], address, root)
            fetches.append({'address': address, 'fetched_on_chain': body.get('_fetched_on_chain'),
                            'match': body.get('match'),
                            'runtime_match': body.get('runtimeMatch'),
                            'creation_match': body.get('creationMatch'),
                            'verified_at': body.get('verifiedAt'), 'sources': len(written),
                            'files': written,
                            'compiler': (body.get('compilation') or {}).get('compilerVersion'),
                            'settings': (body.get('compilation') or {}).get('compilerSettings'),
                            'contract': (body.get('compilation') or {}).get('name')})
            if address == target:
                src = body
        record['stages']['fetch'] = {'state': 'ok', 'fetches': fetches}
    except ConfirmError as exc:
        record['stages']['fetch'] = {'state': 'blocked', 'error': str(exc), 'fetches': fetches}
        return _finish(record, root)

    compilation = src['compilation']
    record['stages']['fetch']['settings'] = compilation.get('compilerSettings')
    record['stages']['fetch']['contract'] = compilation.get('name')
    record['stages']['fetch']['verified_at'] = src.get('verifiedAt')
    version = compilation['compilerVersion'].split('+')[0]
    solc = find_solc(version)
    record['stages']['fetch']['solc_local'] = solc

    # stage: supplements (sibling sources the bundle cannot carry)
    source_root = discover_source_root(source_root)
    if source_root:
        record['source_root'] = source_root
    pairs = list((add or []))
    for rel in (placard.get('reproduction') or {}).get('add_sources') or []:
        if source_root:
            candidate = Path(source_root, Path(rel).name)
            if candidate.is_file():
                pairs.append((rel, str(candidate)))
    try:
        supplemented = add_sources(str(root), pairs)
        record['stages']['supplement'] = {'state': 'ok', 'files': supplemented,
                                          'skipped': 'a file the bundle already carries is never overwritten'}
    except OSError as exc:
        record['stages']['supplement'] = {'state': 'blocked', 'error': str(exc)}
        return _finish(record, root)

    # stage: libs
    supply = discover_libs(libs)
    if forge_std:
        supply['forge-std'] = forge_std
    try:
        added = add_missing_libs(str(root), supply)
        record['stages']['libs'] = {'state': 'ok', 'supplied': sorted(supply), 'files_added': len(added)}
    except ConfirmError as exc:
        record['stages']['libs'] = {'state': 'blocked', 'error': str(exc)}
        return _finish(record, root)

    # stage: build
    toml = write_foundry_toml(str(root), compilation.get('compilerSettings') or {}, solc, version)
    record['stages']['build'] = {'foundry_toml': toml}
    code, log = _run([forge, 'build'], str(root), timeout)
    record['stages']['build'].update({'state': 'ok' if code == 0 else 'blocked', 'exit_code': code,
                                      'log_tail': log[-2500:]})
    if code != 0:
        return _finish(record, root)

    # stage: compare
    deployed = match.load_code(target, rpc or chains.endpoint(chain))
    record['target_code_sha256'] = '0x' + _sha256(deployed)
    record['target_code_bytes'] = len(deployed)
    try:
        record['stages']['compare'] = compare_rebuilt(str(root / 'out'), compilation['name'], deployed)
    except ConfirmError as exc:
        record['stages']['compare'] = {'state': 'blocked', 'error': str(exc)}
        return _finish(record, root)
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
    for item in sorted(Path('reproductions', placard_id).glob('*')):
        if item.is_file():
            shutil.copy(item, target_dir / item.name)
    names = [p.name for p in probes]
    match_test = (placard.get('reproduction') or {}).get('match_test')
    passed, failed, codes, logs = [], [], [], []
    for name in names:
        cmd = [forge, 'test', '--match-path', 'test/%s' % name]
        if match_test:
            cmd += ['--match-test', match_test]
        code, log = _run(cmd, str(root), timeout)
        codes.append(code)
        logs.append('== %s\n%s' % (name, log[-1500:]))
        passed += re.findall(r'^\[PASS\] (\S+)', log, re.M)
        failed += re.findall(r'^\[FAIL[^\]]*\] (\S+)', log, re.M)
    joined = '\n'.join(logs)
    hint = None
    missing = re.findall(r'Source "([^/"]+)/[^"]*" not found', joined)
    if missing:
        hint = 'the probe imports %s; supply it with --lib or a LIB_CANDIDATES entry' % ', '.join(sorted(set(missing)))
    record['stages']['probe'] = {'state': 'ok' if not any(codes) and passed else 'failed',
                                 'exit_codes': codes, 'sources': names, 'match_test': match_test,
                                 'passed': passed, 'failed': failed, 'missing_lib_hint': hint,
                                 'log_tail': joined[-3000:]}

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
    parser.add_argument('--target', default=None, help='an address, or a label containing one; defaults to the placard confirmed_on target')
    parser.add_argument('--register', default=None)
    parser.add_argument('--chain', default='mainnet', choices=sorted(chains.CHAINS))
    parser.add_argument('--workdir', default='work')
    parser.add_argument('--forge', default=DEFAULT_FORGE)
    parser.add_argument('--forge-std', default=None, help='directory holding the forge-std source tree')
    parser.add_argument('--lib', action='append', default=[], metavar='NAME=PATH',
                        help='top the bundle up with a local library, never overwriting verified files')
    parser.add_argument('--add-source', action='append', default=[], metavar='REL=PATH',
                        help='supplement a source file the bundle does not carry, never overwriting a verified file')
    parser.add_argument('--source-root', default=None,
                        help='upstream src dir, used to resolve the add_sources a placard declares')
    parser.add_argument('--source', action='append', default=[], metavar='ADDRESS',
                        help='extra verified source to fetch into the same tree, for probes touching more than the target')
    parser.add_argument('--rpc', default=None)
    args = parser.parse_args(argv)
    libs = {}
    for item in args.lib:
        if '=' not in item:
            parser.error('--lib wants NAME=PATH, got %s' % item)
        name, path = item.split('=', 1)
        libs[name] = path
    placard = {p['id']: p for p in match.load_register(args.register or DEFAULT_REGISTER)}[args.placard]
    extra = (placard.get('reproduction') or {}).get('sources') or []
    add = []
    for item in args.add_source:
        if '=' not in item:
            parser.error('--add-source wants REL=PATH, got %s' % item)
        rel, path = item.split('=', 1)
        add.append((rel, path))
    record = run(args.placard, args.target, args.register, args.chain, args.workdir,
                 args.forge, args.forge_std, args.rpc, libs=libs, sources=extra + args.source,
                 add=add, source_root=args.source_root)
    print(json.dumps({k: record[k] for k in ('placard', 'target', 'verdict', 'record', 'workdir')}, indent=2))
    for stage, body in sorted(record['stages'].items()):
        print('%-8s %s' % (stage, body.get('state')))
    return 0 if record['verdict'] == 'confirmed' else 1


if __name__ == '__main__':
    sys.exit(main())
