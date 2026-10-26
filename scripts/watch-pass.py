#!/usr/bin/env python3
"""One watch pass, printing only what needs a human. Scheduler-friendly.

Runs from anywhere: the repo root is found from this file. Empty stdout means
nothing matched and nothing changed, so a scheduled job configured to deliver
stdout sends nothing on a quiet tick.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'matcher'))
os.chdir(ROOT)

from hazmat import watch  # noqa: E402


def main():
    chain = sys.argv[1] if len(sys.argv) > 1 else 'mainnet'
    db = watch.connect(os.path.join('work', 'watch-%s.sqlite3' % chain))
    result = watch.pass_once(db, chain, sink=os.path.join('work', 'alerts-%s.jsonl' % chain),
                             sheet_dir=os.path.join('work', 'sheets-%s' % chain))
    quiet = not result['matched'] and not result['upgrades'] and not result['errors']
    if quiet:
        return 0
    print('hazmat watch %s: %d scanned, %d matched, %d upgrades' %
          (chain, len(result['scanned']), result['matched'], result['upgrades']))
    for row in db.execute('select * from alerts order by id desc limit ?', (max(result['matched'], 1),)):
        print('  %-7s %s  %s' % (row['kind'], row['address'], row['placards']))
    for error in result['errors'][:5]:
        print('  error: %s' % error)
    return 0


if __name__ == '__main__':
    sys.exit(main())
