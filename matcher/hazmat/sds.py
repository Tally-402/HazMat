"""Render a Safety Data Sheet: the shareable, self-contained report artifact.

The sheet carries its own digest so a third party can re-derive it without
trusting the producer. Tampering with any byte changes the digest.
"""
import hashlib
import html
import json
import re
import sys

PLACEHOLDER = '{SHEET}'
DIGEST_LINE = re.compile(r'sheet sha256 <code>([0-9a-f]{64})</code>')

PAGE = """<!doctype html><meta charset="utf-8">
<title>HazMat Safety Data Sheet {target}</title>
<style>
 body{{font:15px/1.5 ui-monospace,Menlo,monospace;margin:0;padding:2rem;background:#111;color:#e8e8e8}}
 h1{{font-size:1.2rem;margin:0 0 .2rem}} h2{{font-size:.8rem;letter-spacing:.09em;text-transform:uppercase;color:#8a8a8a;margin:2rem 0 .4rem}}
 table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #2a2a2a;padding:.5rem .4rem;text-align:left;vertical-align:top}}
 .id{{color:#ffb020;white-space:nowrap}} code{{color:#7fd1ff;word-break:break-all}} ul{{padding-left:1.2rem;color:#bdbdbd}}
 .banner{{border:1px solid #444;padding:.6rem .8rem;margin:1rem 0;background:#181818}}
 .sel{{color:#9b9b9b;font-size:.85em}}
</style>
<h1>HazMat Safety Data Sheet</h1>
<div>target <code>{target}</code> &middot; family {family}</div>
<div>subject {subject}</div>
{scans}
<div>code sha256 <code>{sha}</code></div>
<div>register {register} placards v{register_digest} &middot; body {body}B &middot; metadata {meta}B excluded &middot; {consts} four-byte constants</div>
<div>anchor {anchor}</div>
<div class="banner"><b>Assertion level: {assertion}.</b> A match is a candidate, not a clearance. {note}</div>
<h2>What was read</h2>
<div class="banner">{coverage}</div>
<table>
<tr><th>placards checked</th><th>classes</th><th>selectors in code</th><th>the register asks about</th><th>otherwise unaccounted</th></tr>
<tr><td>{checked}</td><td>{classes}</td><td>{in_code}</td><td>{asked}</td><td>{unaccounted}</td></tr>
</table>
<h2>Unaccounted selectors (nearest misses)</h2>
<ul class="sel">{misses}</ul>
<h2>Placards</h2>
<table><tr><th>id</th><th>class</th><th>hazard</th><th>tier</th><th>money</th><th>matched by</th></tr>
{rows}</table>
<h2>Not checked</h2><ul>{notchecked}</ul>
<footer><p>sheet sha256 <code>{sheet}</code> &middot; re-derive with <code>hazmat verify</code>; cite the id, the code sha256 and the register digest.</p></footer>
"""


def page_digest(page):
    """The digest the sheet claims, recomputed from its own bytes."""
    if PLACEHOLDER in page:
        return '0x' + hashlib.sha256(page.encode()).hexdigest()
    found = DIGEST_LINE.search(page)
    if not found:
        raise ValueError('no sheet digest line')
    return '0x' + hashlib.sha256(page.replace(found.group(1), PLACEHOLDER, 1).encode()).hexdigest()


def claimed_digest(page):
    found = DIGEST_LINE.search(page)
    return '0x' + found.group(1) if found else None


def anchor_line(report):
    anchor = report.get('register_anchor')
    if not anchor:
        return 'no epoch published yet'
    return 'epoch %s root %s (%s)' % (anchor.get('epoch'), anchor.get('root'), anchor.get('file'))


def subject_line(report):
    """What the target actually is, and where the logic lives."""
    subject = report.get('subject')
    if not subject:
        return 'raw code, not an address, so nothing was resolved'
    kind = subject.get('kind')
    line = '%s <code>%s</code>' % (html.escape(kind), html.escape(subject.get('requested', '')))
    if subject.get('via'):
        line += ' resolved via %s' % html.escape(subject['via'])
    if subject.get('effective') and subject['effective'] != subject.get('requested'):
        line += ' &rarr; effective <code>%s</code>' % html.escape(subject['effective'])
    names = [v.get('name') for v in (subject.get('identity') or {}).values() if v.get('name')]
    if names:
        line += ' &middot; verified as %s' % ', '.join(html.escape(n) for n in names)
    if kind == 'possible-proxy':
        line += ' &middot; the code delegatecalls but no pointer was found, so the logic may sit somewhere this resolver cannot see'
    return line


def scan_table(report):
    rows = report.get('scans') or []
    if len(rows) < 2:
        return ''
    body = []
    for row in rows:
        ident = (row.get('identity') or {}).get('name') or (row.get('identity') or {}).get('state') or ''
        found = ' '.join(m['id'] for m in row.get('matches', [])) or '&ndash;'
        body.append('<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
            html.escape(row.get('role', '')), html.escape(ident), html.escape(row.get('at', '')),
            (row.get('coverage') or {}).get('selectors_in_code', '?'), (row.get('stats') or {}).get('code_bytes', '?'),
            found))
    return ('<h2>Addresses scanned</h2><table><tr><th>role</th><th>identity</th><th>address</th>'
            '<th>selectors</th><th>bytes</th><th>matched</th></tr>%s</table>' % ''.join(body))


def render(report):
    rows = []
    for m in report['matches']:
        selectors = ' '.join(m.get('matched_selectors') or [])
        rows.append('<tr><td class="id">{}</td><td>{} {}</td><td>{}</td><td>{}</td><td>{}</td>'
                    '<td class="sel">{}{}</td></tr>'.format(
                        html.escape(m['id']), m['placard_class'], html.escape(m.get('placard_class_name') or ''),
                        html.escape(m['title']), html.escape(m['assertion']),
                        html.escape(m.get('money_bound', {}).get('expression', 'n/a')),
                        html.escape(selectors),
                        (' &middot; %d absence checks' % m['absent_checked']) if m.get('absent_checked') else ''))
    if not rows:
        rows.append('<tr><td colspan="6">no placard matched. That is not the same as safe.</td></tr>')
    page = PAGE.format(target=html.escape(report['target']), family=html.escape(report.get('family', 'evm')),
                       sha=html.escape(report['code_sha256']), register=report['register_size'],
                       register_digest=html.escape(report.get('register_digest', 'unpinned')),
                       body=report['stats']['body_bytes'], meta=report['stats']['metadata_bytes'],
                       consts=report['stats']['push4_constants'], assertion=html.escape(report['assertion']),
                       note=html.escape(report['assertion'] + ' match only' if report['matches'] else 'nothing matched'),
                       rows='\n'.join(rows),
                       notchecked=''.join('<li>%s</li>' % html.escape(x) for x in report['not_checked']),
                       anchor=html.escape(anchor_line(report)), sheet=PLACEHOLDER,
                       subject=subject_line(report), scans=scan_table(report),
                       coverage=html.escape((report.get('coverage') or {}).get('means', '')),
                       checked=(report.get('coverage') or {}).get('placards_checked', 0),
                       classes=len((report.get('coverage') or {}).get('classes_checked', [])),
                       in_code=(report.get('coverage') or {}).get('selectors_in_code', 0),
                       asked=(report.get('coverage') or {}).get('selectors_the_register_asks_about', 0),
                       unaccounted=(report.get('coverage') or {}).get('selectors_otherwise_unaccounted', 0),
                       misses=''.join('<li><code>%s</code> %s</li>' % (
                           html.escape(m['selector']), html.escape(m['signature'] or 'unindexed'))
                           for m in (report.get('coverage') or {}).get('unaccounted_sample', [])))
    digest = hashlib.sha256(page.encode()).hexdigest()
    return page.replace(PLACEHOLDER, digest), '0x' + digest


def verify(page, expect=None):
    """Return (claimed, recomputed, ok). Optionally against an expected digest."""
    claimed = claimed_digest(page)
    recomputed = page_digest(page)
    ok = bool(claimed) and claimed == recomputed and (expect is None or claimed == expect)
    return claimed, recomputed, ok


if __name__ == '__main__':
    page = sys.stdin.read()
    claimed, recomputed, ok = verify(page, sys.argv[1] if len(sys.argv) > 1 else None)
    print(json.dumps({'claimed': claimed, 'recomputed': recomputed, 'ok': ok}))
    sys.exit(0 if ok else 1)
