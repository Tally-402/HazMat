#!/usr/bin/env python3
"""Write a static snapshot of the app's scan view, so it can be opened from a file.

The app talks to the server with fetch, which a file:// page cannot reach, so the payloads
it would have fetched are baked in behind a tiny fetch shim. Views, prose and layout are the
real ones: this is the app, not a mockup.
"""
import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'matcher'))

from hazmat import match, sds                                            # noqa: E402


def main():
    parser = argparse.ArgumentParser(prog='app-snapshot')
    parser.add_argument('--target', required=True)
    parser.add_argument('--chain', default='mainnet')
    parser.add_argument('--out', required=True)
    parser.add_argument('--register', default=str(ROOT / 'register' / 'placards'))
    args = parser.parse_args()

    report = match.scan(args.target, args.register, chain=args.chain, as_='auto')
    report['register_anchor'] = match.latest_anchor()
    report['register_digest'] = match.register_digest(args.register)
    report['register_size'] = len(match.load_register(args.register))
    register = {'count': report['register_size'], 'placards': [], 'digest': report['register_digest'],
                'anchor': report['register_anchor'],
                'placards': [{'id': p['id'], 'placard_class': p['placard_class'],
                              'placard_class_name': p.get('placard_class_name', ''), 'title': p['title'],
                              'tier': p['tier'],
                              'money': (p.get('money_bound') or {}).get('expression', '')}
                             for p in match.load_register(args.register)]}
    seeds = {'/scan?chain=%s&target=%s' % (args.chain, args.target):
             dict(report, presentation=sds.present(report)),
             '/api/register': register}
    page = (ROOT / 'web' / 'index.html').read_text()
    shim = """<script>
// baked payloads: a file:// page cannot reach the server these views normally fetch from
const SEED = %s;
for (const [path, body] of Object.entries(SEED)) {
  const url = new URL(path, 'http://seeded');
  SEED[url.pathname + url.search] = body;
}
const realFetch = window.fetch;
window.fetch = async (input, init) => {
  const url = new URL(String(input), 'http://seeded');
  const hit = SEED[url.pathname + url.search];
  if (hit) return { ok: true, status: 200, json: async () => hit };
  return realFetch ? realFetch(input, init) : { ok: false, status: 404, json: async () => ({ error: 'unseeded' }) };
};
if (!location.hash) history.replaceState(null, '', '#/scan/%s/%s');
</script>
""" % (json.dumps(seeds), args.chain, args.target)
    # the sheet itself is a data URL here, so the embedded iframe shows the real document
    from hazmat import sds as _sds
    sheet_html, _ = _sds.render(report)
    shim += ('<script>window.SHEET_HREF = "data:text/html;base64,%s";</script>\n'
             % base64.b64encode(sheet_html.encode()).decode())
    # a file:// page cannot resolve /logo.png either
    page = page.replace('src="/logo.png"', 'src="%s"' % _sds.mark_data_uri())
    page = page.replace('<link rel="icon" href="/logo.png">', '')
    page = page.replace('<script>\nconst CLASSES=', shim + '<script>\nconst CLASSES=')
    Path(args.out).write_text(page)
    print('wrote %s (%d bytes)' % (args.out, len(page)))


if __name__ == '__main__':
    sys.exit(main())
