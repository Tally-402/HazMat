"""Serve the paste-a-target page, the sheet, and a JSON API. Standard library only.

    python3 -m hazmat.serve --port 8712

Routes: / (form), /scan (JSON), /sheet (HTML), /pdf (PDF). Read-only: the server
never signs, never writes to a chain, and every response carries the code digest.
"""
import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import json as _json
from pathlib import Path

from . import anchor, chains, match, paths, pdf, sds

DEFAULT_PORT = 8712
# anchored to the repo, not the current directory: the server has to work wherever
# it is launched from, which is how a scheduled or backgrounded process runs it.
ROOT = Path(__file__).resolve().parents[2]


def rooted(path):
    path = Path(path)
    return path if path.is_absolute() else ROOT / path

FORM = """<!doctype html><meta charset="utf-8"><title>HazMat</title>
<style>
 body{font:15px/1.6 ui-monospace,Menlo,monospace;margin:0;padding:2.5rem;background:#111;color:#e8e8e8}
 input,select,button{font:inherit;padding:.45rem .55rem;background:#181818;color:#e8e8e8;border:1px solid #444}
 button{{cursor:pointer}} a{{color:#7fd1ff}} code{{color:#7fd1ff}}
 .note{{color:#9b9b9b;max-width:52rem}}
</style>
<h1>HazMat</h1>
<p class="note">Paste a contract address. You get matched placards and a sheet, matched against the
register at the digest below. A match is a candidate, not a clearance.</p>
<form action="/sheet" method="get">
 <input name="target" size="46" placeholder="0x address, or 0x bytecode" required>
 <select name="chain">%s</select>
 <button>scan</button>
</form>
<p class="note">JSON: <code>/scan?target=0x...</code> &middot; sheet: <code>/sheet?target=0x...</code> &middot; PDF: <code>/pdf?target=0x...</code></p>
"""


def report_for(target, chain='mainnet', as_='auto', register='register/placards', rpc=None):
    return match.scan(target, register, rpc or chains.endpoint(chain), as_=as_)


def _query(path):
    parsed = urlparse(path)
    return parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items()}


def register_payload(register=None):
    register = register or Handler.register
    placards = []
    for path in sorted(Path(register).glob('*.json')):
        row = _json.loads(path.read_text())
        placards.append({'id': row['id'], 'placard_class': row['placard_class'],
                         'placard_class_name': row.get('placard_class_name'), 'title': row['title'],
                         'tier': row['tier'], 'money': (row.get('money_bound') or {}).get('expression', 'n/a')})
    return {'count': len(placards), 'placards': placards, 'anchor': match.latest_anchor(),
            'digest': match.register_digest(register)}


def placard_payload(placard_id, register=None):
    register = register or Handler.register
    path = Path(register, placard_id + '.json')
    if not path.is_file():
        raise match.MatchError('no such placard: %s' % placard_id)
    row = _json.loads(path.read_text())
    records = sorted(rooted('confirmations').glob(placard_id + '-*.json'))
    if records:
        record = _json.loads(records[-1].read_text())
        stages = record.get('stages', {})
        row['confirmation'] = {
            'verdict': record.get('verdict'), 'record': paths.display(records[-1]),
            'probe_tests': (stages.get('probe') or {}).get('passed', []),
            'evidence': (row.get('confirmed_on') or [{}])[0].get('confirmation', {}).get('evidence'),
            'selector_agreement': (row.get('confirmed_on') or [{}])[0].get('confirmation', {}).get('selector_agreement'),
            'fetched_on': ((stages.get('fetch') or {}).get('fetches') or [{}])[0].get('verified_at')}
    return row


def proof_payload(placard_id, register=None, anchor_dir=None):
    register = register or Handler.register
    anchor_dir = anchor_dir or str(rooted('anchors'))
    got = anchor.proof(register, placard_id, anchor_dir=anchor_dir)
    epoch = got['epoch'] or max(1, len(list(Path(anchor_dir).glob('epoch-*.json'))))
    record = anchor.load_epoch(epoch, anchor_dir)
    return {'epoch': record['epoch'], 'leaf': got['leaf'], 'proof': got['proof'], 'root': got['root'],
            'backed_by_a_published_epoch': got['epoch'] is not None,
            'verified': got['root'] == record['root'] and anchor.verify(got['leaf'], got['proof'], record['root'])}


class Handler(BaseHTTPRequestHandler):
    register = str(rooted('register/placards'))
    chain = 'mainnet'
    web_dir = str(rooted('web'))
    server_version = 'hazmat'

    def _send(self, body, content_type='text/html; charset=utf-8', code=200):
        payload = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header('content-type', content_type)
        self.send_header('content-length', str(len(payload)))
        self.send_header('cache-control', 'no-store')
        self.end_headers()
        self.wfile.write(payload)

    def _fail(self, message, code=502):
        self._send(json.dumps({'state': 'blocked', 'error': message}), 'application/json', code)

    def _api(self, path, query):
        """Read-only JSON for the page. No signing, no state."""
        try:
            if path == '/api/register':
                return self._send(json.dumps(register_payload(self.register)), 'application/json')
            if path == '/api/anchors':
                epochs = []
                for item in sorted(rooted('anchors').glob('epoch-*.json'), key=lambda p: int(p.stem.split('-')[1])):
                    row = _json.loads(item.read_text())
                    row.pop('leaves', None)
                    epochs.append(row)
                return self._send(json.dumps({'epochs': epochs}), 'application/json')
            if path == '/api/proof':
                placard_id = (query.get('placard') or '').upper()
                if not placard_id:
                    return self._fail('pass ?placard=HZ-001', 400)
                return self._send(json.dumps(proof_payload(placard_id, self.register)), 'application/json')
            if path.startswith('/api/placard/'):
                placard_id = path.split('/')[-1].upper()
                return self._send(json.dumps(placard_payload(placard_id, self.register)), 'application/json')
        except (match.MatchError, anchor.AnchorError, ValueError) as exc:
            return self._fail(str(exc), 404)
        except OSError as exc:
            return self._fail('read failed: %s' % exc)
        return self._fail('unknown api route: %s' % path, 404)

    def do_GET(self):
        path, query = _query(self.path)
        chain = query.get('chain', self.chain)
        if path == '/' or path == '/index.html':
            page = rooted(self.web_dir) / 'index.html'
            if page.is_file():
                return self._send(page.read_text())
            options = ''.join('<option%s>%s</option>' % (' selected' if c == chain else '', c)
                              for c in sorted(chains.CHAINS))
            return self._send(FORM % options)
        if path.startswith('/api/'):
            return self._api(path, query)
        target = query.get('target') or query.get('code')
        if not target:
            return self._fail('pass ?target=0x...', 400)
        if chain not in chains.CHAINS:
            return self._fail('unknown chain: %s' % chain, 400)
        try:
            report = report_for(target, chain, query.get('as', 'code' if query.get('code') else 'auto'),
                                self.register, query.get('rpc'))
        except match.MatchError as exc:
            return self._fail(str(exc))
        except OSError as exc:
            return self._fail('rpc unreachable: %s' % exc)
        if path == '/scan':
            # the generated prose rides along so the app renders the same sentences as the sheet
            payload = dict(report, presentation=sds.present(report))
            return self._send(json.dumps(payload, indent=2, sort_keys=True), 'application/json')
        page, digest = sds.render(report)
        if path == '/sheet':
            return self._send(page)
        if path == '/pdf':
            self.send_response(200)
            body = pdf.render_pdf(report)
            self.send_header('content-type', 'application/pdf')
            self.send_header('content-length', str(len(body)))
            self.send_header('content-disposition', 'inline; filename="hazmat-%s.pdf"' % report['code_sha256'][:10])
            self.end_headers()
            return self.wfile.write(body)
        return self._fail('unknown route: %s' % path, 404)

    def log_message(self, fmt, *args):
        sys.stderr.write('hazmat %s\n' % (fmt % args))


def make_server(port=DEFAULT_PORT, host='127.0.0.1', register=None, chain='mainnet'):
    # only override when asked: a relative default here would undo the anchoring
    if register:
        Handler.register = register
    Handler.chain = chain
    return ThreadingHTTPServer((host, port), Handler)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat serve')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--register', default=None)
    parser.add_argument('--chain', default='mainnet', choices=sorted(chains.CHAINS))
    args = parser.parse_args(argv)
    server = make_server(args.port, args.host, args.register, args.chain)
    print('serving on http://%s:%d  register %s  chain %s' % (args.host, args.port, args.register, args.chain))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == '__main__':
    sys.exit(main())
