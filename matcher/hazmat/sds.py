"""Render a Safety Data Sheet: the shareable, self-contained report artifact."""
import hashlib
import html
import json

PAGE = """<!doctype html><meta charset="utf-8">
<title>HazMat Safety Data Sheet {target}</title>
<style>
 body{{font:15px/1.5 ui-monospace,Menlo,monospace;margin:0;padding:2rem;background:#111;color:#e8e8e8}}
 h1{{font-size:1.2rem;margin:0 0 .2rem}} h2{{font-size:.8rem;letter-spacing:.09em;text-transform:uppercase;color:#8a8a8a;margin:2rem 0 .4rem}}
 table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #2a2a2a;padding:.5rem .4rem;text-align:left;vertical-align:top}}
 .id{{color:#ffb020;white-space:nowrap}} code{{color:#7fd1ff;word-break:break-all}} ul{{padding-left:1.2rem;color:#bdbdbd}}
 .banner{{border:1px solid #444;padding:.6rem .8rem;margin:1rem 0;background:#181818}}
</style>
<h1>HazMat Safety Data Sheet</h1>
<div>target <code>{target}</code></div>
<div>code sha256 <code>{sha}</code></div>
<div>register {register} placards &middot; body {body}B &middot; metadata {meta}B excluded &middot; {consts} four-byte constants</div>
<div class="banner"><b>Assertion level: pattern.</b> A match is a candidate. {assertion}</div>
<h2>Placards</h2>
<table><tr><th>id</th><th>class</th><th>hazard</th><th>assertion</th><th>money</th></tr>
{rows}</table>
<h2>Not checked</h2><ul>{notchecked}</ul>
<footer><p>sheet sha256 <code>{sheet}</code></p></footer>
"""


def render(report):
    rows = []
    for m in report['matches']:
        rows.append('<tr><td class="id">{}</td><td>{} {}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
            html.escape(m['id']), m['placard_class'], html.escape(m.get('placard_class_name') or ''),
            html.escape(m['title']), html.escape(m['assertion']),
            html.escape(m.get('money_bound', {}).get('expression', 'n/a'))))
    if not rows:
        rows.append('<tr><td colspan="5">no placard matched. That is not the same as safe.</td></tr>')
    page = PAGE.format(target=html.escape(report['target']), sha=html.escape(report['code_sha256']),
                       register=report['register_size'], body=report['stats']['body_bytes'],
                       meta=report['stats']['metadata_bytes'], consts=report['stats']['push4_constants'],
                       assertion=html.escape(report['assertion']), rows='\n'.join(rows),
                       notchecked=''.join('<li>%s</li>' % html.escape(x) for x in report['not_checked']),
                       sheet='{SHEET}')
    digest = hashlib.sha256(page.replace('{SHEET}', '').encode()).hexdigest()
    return page.replace('{SHEET}', digest), '0x' + digest


if __name__ == '__main__':
    import sys
    print(render(json.load(sys.stdin))[0])
