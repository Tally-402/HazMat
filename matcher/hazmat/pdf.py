"""A Safety Data Sheet as a PDF, with no dependencies and no PDF library.

Text-only by design: the sheet is a document. Layout is deterministic, so the
same report always produces the same bytes, which is what makes it citable.
"""
import re
import zlib

from . import logo, sds


def clean(value):
    """Strip the few entities the HTML uses so the text version reads the same."""
    return re.sub(r"&[a-z]+;", lambda m: {"&mdash;": "--", "&middot;": "*", "&rarr;": "->", "&ndash;": "-",
                                         "&amp;": "&", "&lt;": "<", "&gt;": ">"}
                  .get(m.group(0), m.group(0)), str(value))


A4 = (595, 842)
MARGIN = 48
LEADING = 11.5
SIZE = 9.0
WRAP = 104
MAX_LINES = int((A4[1] - 2 * MARGIN) / LEADING)


ASCII = {'\u2014': '-', '\u2013': '-', '\u00b7': '-', '\u2019': "'", '\u2018': "'",
         '\u201c': '"', '\u201d': '"', '\u2026': '...', '\u2192': '->', '\u00a0': ' '}


def escape(text):
    out = []
    for ch in str(text):
        if ch in '()\\':
            out.append('\\' + ch)
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        elif ch in ASCII:
            out.append(ASCII[ch])
        else:
            out.append('?')
    return ''.join(out)


def wrap(text, width=WRAP):
    words, lines, current = str(text).split(), [], ''
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = (current + ' ' + word).strip()
    if current:
        lines.append(current)
    return lines or ['']


def bullet_lines(label, text, indent=2, width=WRAP):
    """A labelled paragraph with a hanging indent, so a wrapped line never repeats the label."""
    prefix = ' ' * indent + (label + ': ' if label else '')
    lines = wrap(clean(text), max(width - len(prefix), 24))
    return [prefix + lines[0]] + [' ' * len(prefix) + line for line in lines[1:]]


def capitalise(text):
    return text.upper() if len(text) < 60 and text.isascii() else text


def lines_for(report):
    """Every line of the document, in order, unwrapped to pages later.

    Same outline and same generated sentences as the HTML sheet, so the two cannot drift.
    """
    out = ['HAZMAT SAFETY DATA SHEET', '']
    subject = report.get('subject') or {}
    identity = ', '.join(v.get('name') for v in (subject.get('identity') or {}).values() if v.get('name'))
    title = report['target'] + ('  (verified as %s)' % identity if identity else '')
    out += wrap(title)
    out += ['']
    if report['matches']:
        out += wrap('Read %s bytes of deployed bytecode and checked it against %s registered hazards. '
                    '%d %s present%s.'
                    % ('{:,}'.format(report['stats']['body_bytes']), report['register_size'], len(report['matches']),
                       'hazard is' if len(report['matches']) == 1 else 'hazards are',
                       ', reproduced against this very contract' if any(m.get('tier') == 'confirmed' and
                       m.get('confirmed_on') for m in report['matches']) else ''))
    else:
        out += wrap('Read %s bytes of deployed bytecode and checked it against %s registered hazards. '
                    'Nothing matched, which is not the same as safe.'
                    % ('{:,}'.format(report['stats']['body_bytes']), report['register_size']))
    out += ['']
    for label, text in sds.summarise(report):
        out += bullet_lines(label, text)
    out += ['', 'ASSERTION LEVEL: ' + report['assertion'].upper()]
    out += wrap('  A match is a candidate, not a clearance: this sheet fingerprints a contract against '
                'registered hazard shapes, it does not audit it. A clean sheet is not the same as safe.', WRAP - 2)
    out += ['', 'ANSWERS TO THE USUAL QUESTIONS']
    out += wrap('  read from the selectors this contract exposes, not from its docs. Every answer says what it '
                'cannot tell you.', WRAP - 2)
    for item in sds.present(report)['answers']:
        out += ['', '  ' + item['question']]
        out += ['    ' + line for line in wrap(clean(item['answer']), WRAP - 4)]
        out += ['    ' + line for line in wrap('seen: ' + (', '.join(item['evidence']) or
                                                            'no matching selector, so this is its shape'), WRAP - 4)]
        out += ['    ' + line for line in wrap('not answered here: ' + item['cannot'], WRAP - 4)]
        if item.get('related'):
            out.append('    related hazard: ' + ', '.join(item['related']))
    out += ['', '  BOTTOM LINE']
    out += wrap('    ' + clean(sds.present(report)['bottom_line']), WRAP - 4)
    checklist = sds.present(report)['checklist']
    if checklist:
        out += ['', '  BEFORE YOU TRUST IT, CHECK']
        for item in checklist:
            out += ['    - ' + line for line in wrap(clean(item), WRAP - 6)]
    out += ['', 'HAZARDS FOUND']
    if not report['matches']:
        out += wrap('  None of the registered hazards are present. That is not the same as safe: the register is '
                    'shaped after a handful of projects, so this contract may simply be unfamiliar to it.', WRAP - 2)
    for m in report['matches']:
        here = (report.get('subject') or {}).get('effective') or report.get('target', '')
        reproduced = [c for c in (m.get('confirmed_on') or []) if here and here.lower() in (c.get('target') or '').lower()]
        out += ['']
        out += wrap('%s  %s' % (m['id'], clean(m['title'])))
        out.append('  class %s %s   %s' % (m['placard_class'], m.get('placard_class_name') or '',
                                           'CONFIRMED ON THIS TARGET' if reproduced else '%s placard' % m.get('tier')))
        if m.get('summary'):
            out += ['  ' + line for line in wrap(clean(m['summary']), WRAP - 2)]
        if m.get('money_bound', {}).get('expression'):
            out += bullet_lines('What is at stake', clean(m['money_bound']['expression']).rstrip('.') + '.')
        if m.get('fix'):
            out += bullet_lines('What to do', m['fix'])
        if reproduced:
            record = (reproduced[0].get('confirmation') or {}).get('record')
            if record:
                out += bullet_lines('Reproduced here', clean(record) + ' - a rebuild of the verified source and '
                                    'the probes in it passed. Confirming behaviour, not intent.')
        precedent = (m.get('provenance') or {}).get('precedent')
        if precedent:
            out += ['  ' + line for line in wrap(clean(precedent).rstrip('.') + '.', WRAP - 2)]
        out += bullet_lines('matched by selectors', ' '.join(m.get('matched_selectors') or []))
    cov = report.get('coverage') or {}
    out += ['', 'WHAT WAS READ']
    out += wrap(clean(cov.get('means', '')), WRAP)
    out += wrap('placards checked %s   classes %s   selectors in code %s   the register asks about %s   '
                'otherwise unaccounted %s'
                % (cov.get('placards_checked', 0), len(cov.get('classes_checked', [])),
                   cov.get('selectors_in_code', 0), cov.get('selectors_the_register_asks_about', 0),
                   cov.get('selectors_otherwise_unaccounted', 0)))
    for miss in (cov.get('unaccounted_sample') or [])[:20]:
        out += ['  ' + line for line in wrap('%s %s' % (miss['selector'], miss['signature'] or 'unnamed'), WRAP - 3)]
    if len(cov.get('unaccounted_sample') or []) > 20:
        out.append('  ... and %d more' % (len(cov['unaccounted_sample']) - 20))
    out += ['', 'NOT CHECKED AT ALL']
    for item in report['not_checked']:
        out += ['  - ' + line for line in wrap(clean(item), WRAP - 4)]
    out += ['', 'THE TECHNICAL PART']
    for label, value in sds.technical_facts(report):
        out += wrap('  %-20s %s' % (label, value), WRAP)
    if len(report.get('scans') or []) > 1:
        out += ['', 'ADDRESSES SCANNED']
        out += wrap('  a proxy reads as two rows: the proxy itself, and the implementation its logic came from', WRAP - 2)
        for row in report['scans']:
            out += wrap('  %-16s %s  %s selectors  %s bytes' % (row.get('role'), row.get('at'),
                       (row.get('coverage') or {}).get('selectors_in_code', '?'),
                       (row.get('stats') or {}).get('code_bytes', '?')))
    out += ['', 'Cite the placard id, the code sha256 and the register digest. The HTML sheet is the artifact '
                'that carries its own digest; this PDF is the same report set for paper.']
    return out


def paginate(lines, size=MAX_LINES):
    return [lines[i:i + size] for i in range(0, len(lines), size)] or [[]]


def render_pdf(report, with_mark=True):
    """Lay the document out and write it. Deterministic: same report, same bytes.

    The mark rides on page one as an image object, composited onto white so no soft mask is
    needed. If the asset is missing the document still renders, without it.
    """
    pages = paginate(lines_for(report))
    mark = None
    if with_mark:
        try:
            mark = logo.pixels()
        except (OSError, ValueError):
            mark = None
    objects = []
    contents = []
    mark_height = 26 if mark else 0
    for index, page in enumerate(pages):
        top = A4[1] - MARGIN - (mark_height if index == 0 else 0)
        body = []
        if mark and index == 0:
            size = 40
            body.append('q %g 0 0 %g %g %g cm /Im0 Do Q'
                        % (size, size, A4[0] - MARGIN - size, A4[1] - MARGIN - size + 4))
        body += ['BT', '/F1 %g Tf %g TL' % (SIZE, LEADING), '%g %g Td' % (MARGIN, top)]
        for line in page:
            body.append('(%s) Tj T*' % escape(line))
        body.append('ET')
        contents.append('\n'.join(body).encode())
    count = len(pages)
    # 1 catalog, 2 pages, then one page + one content object per page, then the font, then the mark
    font_obj = 3 + 2 * count
    mark_obj = font_obj + 1
    kids = ' '.join('%d 0 R' % (3 + 2 * i) for i in range(count))
    objects.append(b'<< /Type /Catalog /Pages 2 0 R >>')
    objects.append(('<< /Type /Pages /Count %d /Kids [%s] >>' % (count, kids)).encode())
    for i in range(count):
        xobject = ' /XObject << /Im0 %d 0 R >>' % mark_obj if (mark and i == 0) else ''
        objects.append(('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] '
                        '/Resources << /Font << /F1 %d 0 R >>%s >> /Contents %d 0 R >>'
                        % (A4[0], A4[1], font_obj, xobject, 4 + 2 * i)).encode())
        stream = contents[i]
        objects.append(b'<< /Length %d >>\nstream\n' % len(stream) + stream + b'\nendstream')
    objects.append(b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>')
    if mark:
        width, height, rgb = mark
        packed = zlib.compress(rgb, 9)
        objects.append(('<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB '
                        '/BitsPerComponent 8 /Filter /FlateDecode /Length %d >>' % (width, height, len(packed))).encode()
                       + b'\nstream\n' + packed + b'\nendstream')

    out = bytearray(b'%PDF-1.4\n')
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b'%d 0 obj\n' % number + body + b'\nendobj\n'
    xref = len(out)
    out += b'xref\n0 %d\n' % (len(objects) + 1)
    out += b'0000000000 65535 f \n'
    for offset in offsets:
        out += b'%010d 00000 n \n' % offset
    out += b'trailer\n<< /Size %d /Root 1 0 R /Info << /Producer (HazMat) >> >>\nstartxref\n%d\n%%%%EOF\n' % (len(objects) + 1, xref)
    return bytes(out)


def page_count(pdf_bytes):
    import re
    return len(re.findall(rb'/Type /Page[^s]', pdf_bytes))
