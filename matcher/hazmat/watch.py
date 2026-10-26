"""Watch a chain for new verified contracts and for upgrades, then alert.

State lives in sqlite. Nothing is broadcast and nothing is published: alerts go to
a JSONL file, to stdout, and to a webhook only if one is given.

    hazmat watch once --chain mainnet        # one pass, for cron
    hazmat watch run --chain mainnet --interval 300
    hazmat watch check --address 0x... --chain mainnet
    hazmat watch status
"""
import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import chains, match, sds

FEED = 'https://sourcify.dev/server/v2/contracts/%s?limit=%d'
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = str(ROOT / 'work' / 'watch.sqlite3')
DEFAULT_ALERTS = str(ROOT / 'work' / 'alerts.jsonl')
WATCHLIST = str(ROOT / 'register' / 'watchlist.json')

SCHEMA = """
create table if not exists seen (
  address text not null, chain text not null, code_sha256 text, first_seen real,
  placards text, alerted integer default 0, kind text default 'new',
  primary key (address, chain));
create table if not exists cursors (chain text primary key, verified_at text);
create table if not exists alerts (
  id integer primary key autoincrement, created real, chain text, address text,
  code_sha256 text, placards text, kind text, sheet text, digest text);
create table if not exists runs (id integer primary key autoincrement, created real,
  chain text, kind text, candidates integer, matched integer, errors text);
"""


def connect(path=DEFAULT_DB):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


def fetch_feed(chain, limit=200, chain_id=None):
    """Newest verified contracts first. The API has no cursor, so we filter by time."""
    url = FEED % (chain_id or chains.chain_id(chain), limit)
    request = urllib.request.Request(url, headers={'user-agent': 'hazmat/0.1'})
    try:
        body = json.loads(urllib.request.urlopen(request, timeout=90).read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError('feed %s on %s: %s' % (exc.code, chain, exc.reason))
    return body.get('results') or []


def candidates(db, chain, entries):
    """Entries past the cursor.

    Deliberately not filtered against `seen`: a contract can be verified again
    after being upgraded, and that re-appearance is exactly how a feed notices a
    code change. Deduplication inside a pass happens because the first
    observation records the hash the second one then compares against.
    """
    row = db.execute('select verified_at from cursors where chain = ?', (chain,)).fetchone()
    since = row['verified_at'] if row else ''
    out = []
    for entry in entries:
        if (entry.get('verifiedAt') or '') <= since:
            continue
        address = (entry.get('address') or '').lower()
        if address:
            out.append(dict(entry, address=address))
    return out


def changed(db, chain, address, code_sha256):
    """True when this address was seen before with a different code hash."""
    row = db.execute('select code_sha256 from seen where address = ? and chain = ?',
                     (address.lower(), chain)).fetchone()
    return bool(row and row['code_sha256'] and code_sha256 and row['code_sha256'] != code_sha256)


def record(db, chain, address, code_sha256, placards, kind='new'):
    db.execute("""insert into seen (address, chain, code_sha256, first_seen, placards, kind)
                  values (?, ?, ?, ?, ?, ?)
                  on conflict(address, chain) do update set code_sha256 = excluded.code_sha256,
                  placards = excluded.placards, kind = excluded.kind""",
               (address.lower(), chain, code_sha256, time.time(), ','.join(placards), kind))
    db.commit()


def observe(db, chain, address, code_sha256, placards, kind='new', sink=None, webhook=None):
    """Record an observation, alerting if this address's code changed under us.

    Both the feed and the watchlist go through here, so an address that appears in
    both cannot have its hash quietly overwritten before the change is noticed.
    """
    row = db.execute('select code_sha256 from seen where address = ? and chain = ?',
                     (address.lower(), chain)).fetchone()
    upgraded = 0
    if row and row['code_sha256'] and code_sha256 and row['code_sha256'] != code_sha256:
        alert(db, chain, address, code_sha256, placards, 'upgrade', None, None, sink, webhook)
        upgraded = 1
    record(db, chain, address, code_sha256, placards, kind)
    return upgraded


def alert(db, chain, address, code_sha256, placards, kind='new', sheet=None, digest=None,
          sink=None, webhook=None):
    row = {'chain': chain, 'address': address, 'code_sha256': code_sha256,
           'placards': placards, 'kind': kind, 'sheet': sheet, 'digest': digest}
    db.execute("""insert into alerts (created, chain, address, code_sha256, placards, kind, sheet, digest)
                  values (?, ?, ?, ?, ?, ?, ?, ?)""",
               (time.time(), chain, address, code_sha256, ','.join(placards), kind, sheet, digest))
    db.execute('update seen set alerted = 1 where address = ? and chain = ?', (address.lower(), chain))
    db.commit()
    if sink:
        Path(sink).parent.mkdir(parents=True, exist_ok=True)
        with open(sink, 'a') as handle:
            handle.write(json.dumps(row, sort_keys=True) + '\n')
    if webhook:
        post(webhook, row)
    return row


def post(url, payload):
    data = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers={'content-type': 'application/json',
                                                              'user-agent': 'hazmat/0.1'})
    try:
        urllib.request.urlopen(request, timeout=30).read()
        return True
    except Exception:
        return False


def inspect(chain, address, register, rpc=None):
    """Code and matches for one address."""
    code = match.load_code(address, rpc or chains.endpoint(chain))
    digest = '0x' + hashlib.sha256(code).hexdigest()
    matches, _ = match.match_code(code, match.load_register(register))
    return {'code_sha256': digest, 'placards': [m['id'] for m in matches]}


def pass_once(db, chain='mainnet', register='register/placards', limit=200, rpc=None,
              sink=DEFAULT_ALERTS, webhook=None, sheet_dir=None, feed=None, inspect_fn=None,
              watchlist=WATCHLIST):
    feed = feed or fetch_feed
    inspector = inspect_fn or (lambda a: inspect(chain, a, register, rpc))
    errors = []
    try:
        entries = feed(chain, limit)
    except RuntimeError as exc:
        errors.append(str(exc))
        entries = []
    todo = candidates(db, chain, entries)
    matched = 0
    upgraded = 0
    for entry in todo:
        address = entry['address']
        try:
            found = inspector(address)
        except match.MatchError as exc:
            errors.append('%s: %s' % (address, exc))
            record(db, chain, address, None, [])
            continue
        # one alert per address per pass: an upgrade outranks a first sighting
        is_upgrade = changed(db, chain, address, found['code_sha256'])
        if not found['placards'] and not is_upgrade:
            record(db, chain, address, found['code_sha256'], found['placards'])
            continue
        sheet = digest = None
        if found['placards'] and sheet_dir:
            report = match.scan(address, register, rpc or chains.endpoint(chain))
            Path(sheet_dir).mkdir(parents=True, exist_ok=True)
            page, digest = sds.render(report)
            sheet = os.path.join(sheet_dir, found['code_sha256'][:18].replace('0x', '') + '.html')
            Path(sheet).write_text(page)
        if found['placards']:
            matched += 1
        upgraded += 1 if is_upgrade else 0
        alert(db, chain, address, found['code_sha256'], found['placards'],
              'upgrade' if is_upgrade else 'new', sheet, digest, sink, webhook)
        record(db, chain, address, found['code_sha256'], found['placards'])
    newest = max([e.get('verifiedAt') or '' for e in entries] or [''])
    if newest:
        db.execute("""insert into cursors (chain, verified_at) values (?, ?)
                      on conflict(chain) do update set verified_at = excluded.verified_at""", (chain, newest))
        db.commit()
    upgraded += check_watchlist(db, register, chain, rpc, sink, webhook, inspector, watchlist)
    db.execute('insert into runs (created, chain, kind, candidates, matched, errors) values (?, ?, ?, ?, ?, ?)',
               (time.time(), chain, 'new+upgrade', len(todo), matched, '; '.join(errors[:10])))
    db.commit()
    return {'candidates': len(todo), 'matched': matched, 'upgrades': upgraded, 'errors': errors,
            'cursor': newest, 'scanned': [e['address'] for e in todo]}


def check_watchlist(db, register, chain, rpc, sink, webhook, inspector, path=WATCHLIST):
    """A watched address whose code changed is an upgrade, and is alerted on."""
    if not path or not Path(path).is_file():
        return 0
    entries = [e for e in json.loads(Path(path).read_text()).get('addresses', []) if e.get('chain') == chain]
    hits = 0
    for entry in entries:
        address = entry['address'].lower()
        try:
            found = inspector(address)
        except match.MatchError:
            continue
        hits += observe(db, chain, address, found['code_sha256'], found['placards'], 'watch', sink, webhook)
    return hits


def status(db):
    return {
        'seen': db.execute('select count(*) c from seen').fetchone()['c'],
        'alerts': db.execute('select count(*) c from alerts').fetchone()['c'],
        'matched_ever': db.execute("select count(*) c from seen where placards != ''").fetchone()['c'],
        'cursors': [dict(r) for r in db.execute('select * from cursors')],
        'last_runs': [dict(r) for r in db.execute('select * from runs order by id desc limit 5')],
        'recent_alerts': [dict(r) for r in db.execute('select * from alerts order by id desc limit 5')],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat watch')
    parser.add_argument('action', choices=['once', 'run', 'status', 'check'])
    parser.add_argument('--chain', default='mainnet', choices=sorted(chains.CHAINS))
    parser.add_argument('--register', default='register/placards')
    parser.add_argument('--db', default=DEFAULT_DB)
    parser.add_argument('--alerts', default=DEFAULT_ALERTS)
    parser.add_argument('--webhook', default=os.environ.get('HAZMAT_WEBHOOK'))
    parser.add_argument('--sheet-dir', default=None)
    parser.add_argument('--limit', type=int, default=200)
    parser.add_argument('--interval', type=int, default=300)
    parser.add_argument('--address', action='append', default=[])
    parser.add_argument('--rpc', default=None)
    args = parser.parse_args(argv)
    db = connect(args.db)
    if args.action == 'status':
        print(json.dumps(status(db), indent=2, sort_keys=True))
        return 0
    if args.action == 'check':
        if not args.address:
            parser.error('check wants --address')
        rows = []
        for address in args.address:
            row = inspect(args.chain, address, args.register, args.rpc)
            rows.append(dict(row, address=address))
        print(json.dumps(rows, indent=2, sort_keys=True))
        return 0
    if args.action == 'once':
        print(json.dumps(pass_once(db, args.chain, args.register, args.limit, args.rpc, args.alerts,
                                   args.webhook, args.sheet_dir), indent=2, sort_keys=True))
        return 0
    while True:
        result = pass_once(db, args.chain, args.register, args.limit, args.rpc, args.alerts,
                           args.webhook, args.sheet_dir)
        print(json.dumps({'at': time.strftime('%H:%M:%S'), 'candidates': result['candidates'],
                          'matched': result['matched'], 'upgrades': result['upgrades'],
                          'errors': len(result['errors'])}))
        sys.stdout.flush()
        time.sleep(args.interval)


if __name__ == '__main__':
    sys.exit(main())
