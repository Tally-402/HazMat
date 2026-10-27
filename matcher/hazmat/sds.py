"""Render a Safety Data Sheet: the shareable, self-contained report artifact.

Editorial rule: a reader who does not know Solidity should get the summary, the hazards
and what to do from the top of the page, and the hex should stay in the technical part at
the bottom. The prose is generated from the report, never hand-written per target, and the
same sentences are used by the PDF so the two cannot drift.

The sheet carries its own digest so a third party can re-derive it without trusting the
producer. Tampering with any byte changes the digest.
"""
import hashlib
import html
import json
import re
import sys

PLACEHOLDER = '{SHEET}'
DIGEST_LINE = re.compile(r'sheet sha256 <code>([0-9a-f]{64})</code>')

STYLE = """
:root{--ink:#16181c;--dim:#5c636e;--line:#dfe3e8;--bg:#fff;--panel:#f6f7f9;--acc:#8a5a00;--warn:#8a1f1f}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:16px/1.62 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:46rem;margin:0 auto;padding:3rem 1.4rem 5rem}
h1{font-size:1.9rem;line-height:1.2;margin:.2rem 0 .4rem;letter-spacing:-.01em}
h2{font-size:1.15rem;margin:2.6rem 0 .7rem;padding-bottom:.35rem;border-bottom:1px solid var(--line)}
h3{font-size:1rem;margin:1.6rem 0 .3rem}
p{margin:.6rem 0}
ul{margin:.4rem 0 .9rem;padding-left:1.15rem}
li{margin:.3rem 0}
small,.dim{color:var(--dim)}
.kicker{font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
.lede{border-bottom:3px solid var(--ink);padding-bottom:1.1rem;margin-bottom:1.6rem}
.standfirst{font-size:1.08rem;margin:.7rem 0 0}
.facts{display:flex;flex-wrap:wrap;gap:.4rem 1.4rem;margin:.9rem 0 0;font-size:.82rem}
.badge{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:.05rem .55rem;
  font-size:.75rem;color:var(--dim);white-space:nowrap}
.badge.good{border-color:#1f6f43;color:#1f6f43}
.badge.bad{border-color:var(--warn);color:var(--warn)}
.banner{background:var(--panel);border-left:3px solid var(--acc);padding:.7rem .9rem;margin:1.2rem 0;font-size:.92rem}
.hazard{border:1px solid var(--line);border-radius:6px;padding:1rem 1.1rem;margin:1.1rem 0}
.hazard h3{margin-top:0}
.hazard .id{font-weight:600;color:var(--acc)}
.hazard .why{border-left:2px solid var(--line);padding-left:.7rem;margin:.6rem 0;color:var(--dim);font-size:.94rem}
.evidence{font-size:.82rem;color:var(--dim);margin-top:.7rem}
table{border-collapse:collapse;width:100%;margin:.7rem 0;font-size:.9rem}
th,td{text-align:left;vertical-align:top;border-bottom:1px solid var(--line);padding:.45rem .5rem}
th{font-weight:600;color:var(--dim);font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}
td.num{text-align:right;font-variant-numeric:tabular-nums}
code{font:0.88em ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--panel);padding:0 .25rem;border-radius:3px}
ul.sel{columns:2;font-size:.85rem;color:var(--dim);list-style:none;padding-left:0}
ul.sel li{margin:.15rem 0}
details{margin:.6rem 0}
summary{cursor:pointer;color:var(--dim);font-size:.9rem}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);font-size:.85rem;color:var(--dim)}
@media print{body{font-size:11pt}main{padding:0}.hazard{break-inside:avoid}h2{break-after:avoid}}
"""

PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HazMat Safety Data Sheet {target}</title>
<style>{style}</style>
<main>
<header class="lede">
  <div class="kicker">HazMat &middot; safety data sheet</div>
  <h1>{headline}</h1>
  <p class="standfirst">{standfirst}</p>
  <div class="facts">{badges}</div>
  <p class="dim" style="font-size:.82rem">{subject}</p>
</header>

<div class="banner"><b>Assertion level: {assertion}.</b> A match is a candidate, not a clearance:
this sheet fingerprints a contract against registered hazard shapes, it does not audit it.
A clean sheet is not the same as safe.</div>

<section>
<h2>Summary</h2>
<ul>{summary}</ul>
</section>

<section>
<h2>{hazards_heading}</h2>
{hazards}
</section>

<section>
<h2>What was read</h2>
<p>{coverage_means}</p>
<table>
<tr><th>placards checked</th><th>classes</th><th>selectors in code</th><th>the register asks about</th><th>otherwise unaccounted</th></tr>
<tr><td class="num">{checked}</td><td class="num">{classes}</td><td class="num">{in_code}</td><td class="num">{asked}</td><td class="num">{unaccounted}</td></tr>
</table>
<p class="dim">{coverage_note}</p>
<details><summary>Unaccounted selectors &mdash; the nearest misses ({misses_count}). These are in the code and no registered hazard asks about them.</summary>
<ul class="sel">{misses}</ul></details>
</section>

<section>
<h2>Not checked at all</h2>
<ul>{notchecked}</ul>
</section>

<section>
<h2>The technical part</h2>
<p class="dim" id="pins">register {register} placards v{register_digest} · anchor {anchor} · body {body}B read, {meta}B of metadata excluded, {consts} four-byte constants. These are the strings to quote when citing this sheet.</p>
<table>{technical}</table>
{scans}
</section>

<footer>
<p>sheet sha256 <code>{sheet}</code></p>
<p>Re-derive it with <code>hazmat verify --sheet &lt;this file&gt;</code> &mdash; the digest is over these bytes, so any edit shows up.
To cite this in writing, quote the placard id, the code sha256 and the register digest, all above.</p>
</footer>
</main>
</html>
"""


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
    line = '%s <code>%s</code>' % (html.escape(str(kind)), html.escape(subject.get('requested', '')))
    if subject.get('via'):
        line += ' resolved via %s' % html.escape(subject['via'])
    if subject.get('effective') and subject['effective'] != subject.get('requested'):
        line += ' &rarr; logic at <code>%s</code>' % html.escape(subject['effective'])
    names = [v.get('name') for v in (subject.get('identity') or {}).values() if v.get('name')]
    if names:
        line += ' &middot; verified as %s' % ', '.join(html.escape(n) for n in names)
    if kind == 'possible-proxy':
        line += ' &middot; the code delegatecalls but no pointer was found, so the logic may sit somewhere this resolver cannot see'
    return line


def subject_plain(report):
    """The same fact, in one sentence of English, for the summary."""
    subject = report.get('subject') or {}
    chain = report.get('chain') or 'the chain'
    if not subject:
        return 'raw code, not an address on a chain, so nothing was resolved around it'
    kind = subject.get('kind')
    if kind == 'possible-proxy':
        return ('a contract that delegatecalls, but the pointer to its logic was not found, so '
                'anything below may describe only part of what runs')
    if subject.get('effective') and subject['effective'] != subject.get('requested'):
        return ('a proxy: what you call goes to the logic at %s, and that is what was read'
                % subject['effective'])
    return 'a plain contract on %s, read from its bytecode' % (subject.get('chain') or chain)


def here_address(report):
    return ((report.get('subject') or {}).get('effective') or report.get('target') or '').lower()


def reproduced_here(match, report):
    here = here_address(report)
    return [c for c in (match.get('confirmed_on') or [])
            if here and here in (c.get('target') or '').lower()]


def by_importance(report):
    """Reproduced on this target first, then confirmed anywhere, then by class."""
    def key(match):
        return (0 if reproduced_here(match, report) else 1,
                0 if match.get('tier') == 'confirmed' else 1,
                match.get('placard_class', 9), match.get('id', ''))
    return sorted(report['matches'], key=key)


def confidence(match, report):
    if reproduced_here(match, report):
        return 'confirmed on this very target: it was rebuilt and reproduced here'
    if match.get('tier') == 'confirmed':
        return 'confirmed somewhere: a reproduction ran against a different deployment'
    return 'pattern only: the selectors are present, nothing was reproduced'


def summarise(report):
    """The plain-English summary. Bullets of (label, sentence). Shared with the PDF."""
    matches = by_importance(report)
    total = report.get('register_size', 0)
    confirmed_here = [m for m in matches if reproduced_here(m, report)]
    bullets = []
    bullet = lambda label, text: bullets.append((label, text))            # noqa: E731

    bullet('What this is', 'It is %s.' % subject_plain(report))
    if not matches:
        bullet('What matched', 'Nothing. None of the %d registered hazards are present in this bytecode.' % total)
        bullet('What that means', 'Unfamiliar rather than sound. The register is shaped after a small number of '
                                  'projects, so a contract can be perfectly normal and still match nothing. '
                                  'A famous example on this register: The DAO, EtherDelta and Fomo3D all match '
                                  'nothing.')
        return bullets
    names = ', '.join('%s (%s)' % (m['id'], m.get('placard_class_name') or 'hazard') for m in matches[:4])
    bullet('What matched', '%d of the %d registered hazards %s present: %s.'
           % (len(matches), total, 'is' if len(matches) == 1 else 'are', names))
    if confirmed_here:
        bullet('How sure', '%s %s reproduced against this exact contract, not a lookalike.'
               % (', '.join(m['id'] for m in confirmed_here), 'was' if len(confirmed_here) == 1 else 'were'))
    elif any(m.get('tier') == 'confirmed' for m in matches):
        bullet('How sure', 'The hazards are confirmed in general, but on other deployments, so treat them as '
                           'strong fits rather than proven here.')
    else:
        bullet('How sure', 'Low: these are selector fingerprints only. Somebody still has to read the code.')
    top = matches[0]
    bullet('The sharpest one', '%s &mdash; %s' % (top['title'], '')
           if False else '%s: %s' % (top['id'], top['title']))
    if top.get('money_bound', {}).get('expression'):
        bullet('What is at stake', top['money_bound']['expression'].rstrip('.') + '.')
    if top.get('provenance', {}).get('precedent'):
        bullet('Precedent', top['provenance']['precedent'].rstrip('.') + '.')
    fixes = []
    for match in matches:
        fix = (match.get('fix') or '').strip()
        if fix and fix not in fixes:
            fixes.append(fix)
    if fixes:
        bullet('What to do about it', fixes[0])
        for extra in fixes[1:3]:
            bullet('Also', extra)
    return bullets


def technical_facts(report):
    coverage = report.get('coverage') or {}
    anchor = report.get('register_anchor') or {}
    facts = [
        ('target', report['target']),
        ('family', report.get('family', 'evm')),
        ('code sha256', report['code_sha256']),
        ('body bytes read', str(report['stats']['body_bytes'])),
        ('metadata excluded', '%s bytes (CBOR trailer, appended after compilation)' % report['stats']['metadata_bytes']),
        ('four-byte constants', str(report['stats']['push4_constants'])),
        ('register', '%d placards v%s' % (report['register_size'], report.get('register_digest', 'unpinned'))),
        ('anchor', anchor_line(report)),
        ('register digest', report.get('register_digest', 'unpinned')),
    ]
    if anchor.get('root'):
        facts.append(('anchor root', anchor['root']))
    facts.append(('selector index', '%d names, a convenience reading and not verification' % coverage.get('named_index_size', 0)))
    return facts


def scan_table(report):
    rows = report.get('scans') or []
    if len(rows) < 2:
        return ''
    body = []
    for row in rows:
        ident = (row.get('identity') or {}).get('name') or (row.get('identity') or {}).get('state') or ''
        found = ', '.join(m['id'] for m in row.get('matches', [])) or '&ndash;'
        body.append('<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td class="num">%s</td><td class="num">%s</td><td>%s</td></tr>' % (
            html.escape(str(row.get('role', ''))), html.escape(ident), html.escape(row.get('at', '')),
            (row.get('coverage') or {}).get('selectors_in_code', '?'), (row.get('stats') or {}).get('code_bytes', '?'),
            found))
    return ('<h2>Addresses scanned</h2><p class="dim">A proxy reads as two rows: the proxy itself, and the '
            'implementation its logic was inherited from.</p><table><tr><th>role</th><th>identity</th><th>address</th>'
            '<th>selectors</th><th>bytes</th><th>matched</th></tr>%s</table>' % ''.join(body))


def hazard_card(match, report):
    """One hazard, plain prose first, evidence last."""
    reproduced = reproduced_here(match, report)
    badges = ['class %s %s' % (match['placard_class'], match.get('placard_class_name') or '')]
    badges.append('confirmed on this target' if reproduced else '%s placard' % match.get('tier', 'pattern'))
    if match.get('absent_checked'):
        badges.append('%d absence checks' % match['absent_checked'])
    parts = ['<article class="hazard" id="%s">' % html.escape(match['id']),
             '<h3><span class="id">%s</span> &middot; %s</h3>' % (html.escape(match['id']), html.escape(match['title']))]
    parts.append('<div>%s</div>' % ' '.join('<span class="badge%s">%s</span>'
                 % (' good' if b == 'confirmed on this target' else '', html.escape(b)) for b in badges))
    if match.get('summary'):
        parts.append('<p>%s</p>' % html.escape(match['summary']))
    if match.get('money_bound', {}).get('expression'):
        parts.append('<p><b>What is at stake:</b> %s.</p>' % html.escape(match['money_bound']['expression'].rstrip('.')))
    if match.get('fix'):
        parts.append('<p><b>What to do:</b> %s</p>' % html.escape(match['fix']))
    if reproduced:
        record = (reproduced[0].get('confirmation') or {}).get('record')
        if record:
            parts.append('<p class="evidence">Reproduced here: <code>%s</code> &mdash; a rebuild of the verified '
                         'source and the probes in it passed. Confirming behaviour, not intent.</p>' % html.escape(record))
    provenance = match.get('provenance') or {}
    if provenance.get('precedent'):
        parts.append('<p class="why">%s</p>' % html.escape(provenance['precedent'].rstrip('.') + '.'))
    parts.append('<div class="evidence">matched by selectors <code>%s</code>%s</div>'
                 % (html.escape(' '.join(match.get('matched_selectors') or [])),
                    ' &middot; first observed on %s' % html.escape(provenance['specimen'])
                    if provenance.get('specimen') else ''))
    parts.append('</article>')
    return ''.join(parts)


def present(report):
    """The generated prose, in one place, so the sheet and the app cannot drift.

    Returns plain strings (no markup) plus per-hazard blocks; both renderers escape their own.
    """
    coverage = report.get('coverage') or {}
    matches = by_importance(report)
    subject = report.get('subject') or {}
    identity = ', '.join(v.get('name') for v in (subject.get('identity') or {}).values() if v.get('name'))
    if matches:
        standfirst = ('Read %s bytes of deployed bytecode and checked it against %d registered hazards. '
                      '%d %s present%s.' % ('{:,}'.format(report['stats']['body_bytes']), report['register_size'],
                                            len(matches), 'hazard is' if len(matches) == 1 else 'hazards are',
                                            ', reproduced against this very contract'
                                            if any(reproduced_here(m, report) for m in matches)
                                            else ', none of them reproduced here'))
    else:
        standfirst = ('Read %s bytes of deployed bytecode and checked it against %d registered hazards. '
                      'Nothing matched, which is not the same as safe.'
                      % ('{:,}'.format(report['stats']['body_bytes']), report['register_size']))
    hazards = []
    for match in matches:
        reproduced = reproduced_here(match, report)
        badges = ['class %s %s' % (match['placard_class'], match.get('placard_class_name') or '')]
        if reproduced:
            badges.append('confirmed on this target')
        else:
            badges.append('%s placard' % match.get('tier', 'pattern'))
        if match.get('absent_checked'):
            badges.append('%d absence checks' % match['absent_checked'])
        record = (reproduced[0].get('confirmation') or {}).get('record') if reproduced else None
        hazards.append({'id': match['id'], 'title': match['title'], 'class': match['placard_class'],
                        'class_name': match.get('placard_class_name') or '', 'badges': badges,
                        'summary': match.get('summary') or '', 'fix': match.get('fix') or '',
                        'tier': match.get('tier'), 'confirmed_here': bool(reproduced),
                        'money': (match.get('money_bound') or {}).get('expression') or '',
                        'precedent': (match.get('provenance') or {}).get('precedent') or '',
                        'evidence': ('Reproduced here: %s - a rebuild of the verified source and the probes in '
                                     'it passed. Confirming behaviour, not intent.' % record) if record else '',
                        'matched_by': match.get('matched_selectors') or []})
    return {
        'headline': report['target'] + (' (verified as %s)' % identity if identity else ''),
        'identity': identity,
        'standfirst': standfirst,
        'badges': ['%s on %s' % (subject.get('kind', 'target'),
                                 subject.get('chain') or report.get('chain') or 'chain unstated'),
                   '%s bytes of code' % report['stats']['body_bytes'],
                   '%s of %s hazards' % (len(matches), report['register_size']),
                   anchor_line(report)],
        'summary': [{'label': label, 'text': text} for label, text in summarise(report)],
        'hazards': hazards,
        'subject_plain': subject_plain(report),
        'coverage_means': coverage.get('means', ''),
        'coverage_note': ('%s of the %s selectors in this contract are asked about by some placard; the other %s '
                          'are listed so you can see what was skipped.'
                          % (coverage.get('selectors_the_register_asks_about', 0),
                             coverage.get('selectors_in_code', 0), coverage.get('selectors_otherwise_unaccounted', 0))),
        'not_checked': list(report.get('not_checked') or []),
        'pins': ('register %d placards v%s \u00b7 anchor %s \u00b7 body %sB read, %sB of metadata excluded, '
                 '%s four-byte constants' % (report['register_size'], report.get('register_digest', 'unpinned'),
                                             anchor_line(report), report['stats']['body_bytes'],
                                             report['stats']['metadata_bytes'], report['stats']['push4_constants'])),
        'technical': [{'label': k, 'value': str(v)} for k, v in technical_facts(report)],
    }


def render(report):
    coverage = report.get('coverage') or {}
    matches = by_importance(report)
    subject = report.get('subject') or {}
    identity = ', '.join(v.get('name') for v in (subject.get('identity') or {}).values() if v.get('name'))
    prose = present(report)
    headline = html.escape(report['target'])
    if prose['identity']:
        headline += ' <span class="badge">verified as %s</span>' % html.escape(prose['identity'])
    standfirst = prose['standfirst']
    badges = prose['badges']
    page = PAGE.format(
        style=STYLE, target=html.escape(report['target']), headline=headline, standfirst=standfirst,
        badges=''.join('<span class="badge">%s</span>' % html.escape(str(b)) for b in badges),
        subject=subject_line(report), assertion=html.escape(report['assertion']),
        summary=''.join('<li><b>%s</b>%s %s</li>' % (html.escape(b['label']), ':' if b['label'] else '', b['text'])
                        for b in prose['summary']),
        hazards_heading='Hazards found' if matches else 'Hazards found',
        hazards=''.join(hazard_card(m, report) for m in matches) if matches else
                '<p>None of the registered hazards are present. That is not the same as safe: the register is '
                'shaped after a handful of projects, so this contract may simply be unfamiliar to it.</p>',
        coverage_means=html.escape(coverage.get('means', '')),
        coverage_note=html.escape(prose['coverage_note']),
        checked=coverage.get('placards_checked', 0), classes=len(coverage.get('classes_checked', [])),
        in_code=coverage.get('selectors_in_code', 0), asked=coverage.get('selectors_the_register_asks_about', 0),
        unaccounted=coverage.get('selectors_otherwise_unaccounted', 0),
        misses_count=len(coverage.get('unaccounted_sample') or []),
        misses=''.join('<li><code>%s</code> %s</li>' % (html.escape(m['selector']), html.escape(m['signature'] or 'unnamed'))
                       for m in (coverage.get('unaccounted_sample') or [])),
        notchecked=''.join('<li>%s</li>' % html.escape(x) for x in report['not_checked']),
        technical=''.join('<tr><td>%s</td><td><code>%s</code></td></tr>' % (html.escape(k), html.escape(str(v)))
                          for k, v in technical_facts(report)),
        register=report['register_size'], register_digest=html.escape(report.get('register_digest', 'unpinned')),
        anchor=html.escape(anchor_line(report)), body=report['stats']['body_bytes'],
        meta=report['stats']['metadata_bytes'], consts=report['stats']['push4_constants'],
        scans=scan_table(report), sheet=PLACEHOLDER)
    digest = hashlib.sha256(page.encode()).hexdigest()
    return page.replace(PLACEHOLDER, digest), '0x' + digest


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
