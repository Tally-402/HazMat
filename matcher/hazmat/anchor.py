"""Merkle-anchor the register, and prove a single placard belongs to an epoch.

Deterministic by construction, and reproducible byte-for-byte from another
implementation, which is the point: the root is only worth publishing if anyone
can recompute it.

Rules, frozen:
  leaf  = keccak256(canonical json of the placard, keys sorted, no spaces)
  node  = leaves sorted lexicographically by hash; odd node duplicated; parent =
          keccak256(left || right) over the 64 raw bytes
  root  = the single remaining node
  proof = the sibling hash at each level, with no side flags, because every pair
          is sorted before hashing
Canonicalisation is on parsed content, not file bytes, so reformatting a placard
file does not move the root, while changing a field does.
"""
import argparse
import json
import sys
from pathlib import Path

from . import keccak, match

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = str(ROOT / 'anchors')


class AnchorError(Exception):
    pass


def leaf_of(placard):
    canonical = json.dumps(placard, sort_keys=True, separators=(',', ':')).encode()
    return keccak.keccak256(canonical)


def leaves_of(register_dir):
    out = []
    for path in sorted(Path(register_dir).glob('*.json')):
        placard = json.loads(path.read_text())
        out.append({'id': placard['id'], 'file': path.name, 'leaf': '0x' + leaf_of(placard).hex()})
    return sorted(out, key=lambda row: row['leaf'])


def bare(value):
    return value[2:] if isinstance(value, str) and value.startswith('0x') else value


def parent(left_hex, right_hex):
    left, right = bytes.fromhex(bare(left_hex)), bytes.fromhex(bare(right_hex))
    low, high = (left, right) if left <= right else (right, left)
    return keccak.keccak256(low + high).hex()


def next_level(level):
    """One level up: sort, duplicate the last node if odd, then pair by index.

    Sort then duplicate - in that order, and shared with the proof walk, so the
    tree and the walk cannot drift apart. Sorting first also makes an odd level's
    duplication deterministic instead of depending on a parent's hash order.
    """
    ordered = sorted(level)
    if len(ordered) % 2:
        ordered = ordered + [ordered[-1]]
    return [parent(ordered[i], ordered[i + 1]) for i in range(0, len(ordered), 2)]


def build(leaves):
    """Levels of the tree, bottom up. An empty register has a root of None.

    Roots and leaves carry a 0x prefix everywhere they are published, like every
    other hash this repo prints; `parent` strips it because fromhex wants it gone.
    """
    if not leaves:
        return [], None
    level = sorted(bare(leaf) for leaf in leaves)
    levels = [list(level)]
    while len(level) > 1:
        level = next_level(level)
        levels.append(sorted(level))
    return levels, '0x' + level[0]


def published_epoch_for(root, anchor_dir=None):
    """Which published epoch, if any, has this root. A root nobody published is not a claim."""
    for path in sorted(Path(anchor_dir or DEFAULT_DIR).glob('epoch-*.json')):
        try:
            record = json.loads(path.read_text())
        except ValueError:
            continue
        if record.get('root') == root:
            return record['epoch']
    return None


def proof(register_dir, placard_id, epoch=None, anchor_dir=None):
    """Sibling hashes from the leaf to the root, no side flags: pairs are sorted.

    With no epoch the tree is today's register. With one it is the leaf set that epoch
    published: once the register grows, a proof into an old epoch cannot be recomputed
    from today's tree, only from the leaves that epoch actually recorded.
    """
    if epoch is None:
        rows = leaves_of(register_dir)
        digest = match.register_digest(register_dir)
    else:
        record = load_epoch(epoch, anchor_dir) if anchor_dir else load_epoch(epoch)
        rows = record['leaves']
        digest = record['register_digest']
        if not any(row['id'] == placard_id for row in rows):
            raise AnchorError('%s is not in epoch %s' % (placard_id, record['epoch']))
    leaves = [row['leaf'] for row in rows]
    target = next((row for row in rows if row['id'] == placard_id), None)
    if target is None:
        raise AnchorError('no such placard: %s' % placard_id)
    node = bare(target['leaf'])                     # the walk is bare; the output is prefixed
    level = sorted(bare(leaf) for leaf in leaves)
    siblings = []
    while len(level) > 1:
        ordered = sorted(level)
        if len(ordered) % 2:
            ordered = ordered + [ordered[-1]]
        index = ordered.index(node)
        sibling = ordered[index + 1] if index % 2 == 0 else ordered[index - 1]
        siblings.append(sibling)
        node = parent(ordered[index], sibling)
        level = [parent(ordered[i], ordered[i + 1]) for i in range(0, len(ordered), 2)]
    root = '0x' + node
    return {'placard': placard_id, 'leaf': target['leaf'], 'proof': ['0x' + s for s in siblings],
            'root': root, 'epoch': epoch if epoch is not None else published_epoch_for(root, anchor_dir),
            'register_digest': digest}


def verify(leaf_hex, siblings, root):
    """Recompute a root from a leaf and its siblings. Sorted pairs, so no sides."""
    node = bare(leaf_hex)
    for sibling in siblings:
        node = parent(node, sibling)
    return node == bare(root)


def write_epoch(register_dir, out_dir=DEFAULT_DIR, epoch=1, note=None):
    rows = leaves_of(register_dir)
    leaves = [row['leaf'] for row in rows]
    levels, root = build(leaves)
    if root is None:
        raise AnchorError('the register is empty')
    record = {'epoch': epoch, 'algorithm': 'keccak256/sorted-pair/duplicate-odd',
              'leaf_rule': 'keccak256(canonical json, keys sorted, separators (",", ":"))',
              'register_digest': match.register_digest(register_dir), 'placards': len(rows),
              'root': root, 'leaves': rows, 'notes': note}
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = Path(out_dir) / ('epoch-%d.json' % epoch)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return record, str(path)


def load_epoch(path_or_epoch, out_dir=DEFAULT_DIR):
    path = Path(path_or_epoch) if Path(str(path_or_epoch)).exists() else Path(out_dir) / ('epoch-%s.json' % path_or_epoch)
    if not path.is_file():
        raise AnchorError('no anchor record at %s' % path)
    return json.loads(path.read_text())


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat anchor')
    parser.add_argument('action', choices=['root', 'prove', 'verify', 'list'])
    parser.add_argument('--register', default=str(ROOT / 'register' / 'placards'))
    parser.add_argument('--dir', default=DEFAULT_DIR)
    parser.add_argument('--epoch', default=None)
    parser.add_argument('--placard', default=None)
    parser.add_argument('--proof', default=None)
    parser.add_argument('--leaf', default=None)
    parser.add_argument('--root', default=None)
    args = parser.parse_args(argv)
    if args.action == 'list':
        rows = []
        for path in sorted(Path(args.dir).glob('epoch-*.json')):
            row = json.loads(path.read_text())
            row.pop('leaves', None)
            rows.append(row)
        print(json.dumps(rows, indent=2, sort_keys=True))
        return 0
    if args.action == 'root':
        epoch = int(args.epoch or (len(list(Path(args.dir).glob('epoch-*.json'))) + 1))
        record, path = write_epoch(args.register, args.dir, epoch)
        print(json.dumps({k: record[k] for k in ('epoch', 'placards', 'root', 'register_digest')}, indent=2))
        print('written %s' % path)
        return 0
    if args.action == 'prove':
        if not args.placard:
            parser.error('prove wants --placard')
        got = proof(args.register, args.placard, epoch=int(args.epoch) if args.epoch else None,
                    anchor_dir=args.dir)
        print(json.dumps(got, indent=2, sort_keys=True))
        return 0
    if args.action == 'verify':
        if not (args.proof and args.root and args.leaf) and not args.proof:
            parser.error('verify wants --proof, and --leaf/--root when the proof file has no root')
        if args.proof.endswith('.json'):
            body = json.loads(Path(args.proof).read_text())
            leaf_hex, siblings, root = body['leaf'], body['proof'], body.get('root') or args.root
        else:
            leaf_hex, siblings, root = args.leaf, json.loads(args.proof), args.root
        if not root:
            parser.error('no root in the proof and none supplied')
        ok = verify(leaf_hex, siblings, root)
        print(json.dumps({'leaf': leaf_hex, 'root': root, 'ok': ok}))
        return 0 if ok else 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
