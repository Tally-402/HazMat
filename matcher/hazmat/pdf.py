"""A Safety Data Sheet as a PDF, with no dependencies and no PDF library.

Text-only by design: the sheet is a document. Layout is deterministic, so the
same report always produces the same bytes, which is what makes it citable.
"""
A4 = (595, 842)
MARGIN = 48
LEADING = 11.5
SIZE = 9.0
WRAP = 104
MAX_LINES = int((A4[1] - 2 * MARGIN) / LEADING)


def escape(text):
    out = []
    for ch in str(text):
        if ch in '()\\':
            out.append('\\' + ch)
        elif 32 <= ord(ch) < 127:
            out.append(ch)
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


def capitalise(text):
    return text.upper() if len(text) < 60 and text.isascii() else text


def lines_for(report):
    """Every line of the document, in order, unwrapped to pages later."""
    out = ['HAZMAT SAFETY DATA SHEET', '']
    out += wrap('target %s   family %s' % (report['target'], report.get('family', 'evm')))
    out += wrap('code sha256 %s' % report['code_sha256'])
    out += wrap('register %s placards   body %s bytes   metadata %s excluded   %s four-byte constants'
                % (report['register_size'], report['stats']['body_bytes'],
                   report['stats']['metadata_bytes'], report['stats']['push4_constants']))
    out += wrap('assertion level: %s' % report['assertion']) + ['']
    cov = report.get('coverage') or {}
    out.append('WHAT WAS READ')
    out += wrap('placards checked %s   classes %s   selectors in code %s   the register asks about %s   otherwise unaccounted %s'
                % (cov.get('placards_checked', 0), len(cov.get('classes_checked', [])),
                   cov.get('selectors_in_code', 0), cov.get('selectors_the_register_asks_about', 0),
                   cov.get('selectors_otherwise_unaccounted', 0)))
    for miss in (cov.get('unaccounted_sample') or [])[:12]:
        out += ['  ' + line for line in wrap('%s %s' % (miss['selector'], miss['signature'] or 'unindexed'), WRAP - 3)]
    subject = report.get('subject')
    out += ['', 'SUBJECT', '']
    if not subject:
        out += wrap('raw code, not an address, so nothing was resolved')
    else:
        out += wrap('%s %s' % (subject.get('kind'), subject.get('requested')))
        if subject.get('via'):
            out += wrap('resolved via %s' % subject['via'])
        if subject.get('effective') and subject['effective'] != subject.get('requested'):
            out += wrap('effective %s' % subject['effective'])
        for value in (subject.get('identity') or {}).values():
            if value.get('name'):
                out += wrap('verified as %s (%s)' % (value['name'], value.get('match') or 'match state unknown'))
    if len(report.get('scans') or []) > 1:
        out.append('ADDRESSES SCANNED')
        for row in report['scans']:
            out += wrap('  %-16s %s  %s selectors  %s bytes' % (row.get('role'), row.get('at'),
                       (row.get('coverage') or {}).get('selectors_in_code', '?'),
                       (row.get('stats') or {}).get('code_bytes', '?')))
    out += ['', 'ASSERTION']
    out += wrap('a match is a candidate, not a clearance. Nothing here claims the contract is safe.')
    out += ['', 'PLACARDS']
    if not report['matches']:
        out += wrap('no placard matched. That is not the same as safe.')
    for m in report['matches']:
        out += ['', '%s  class %s %s  tier %s  [%s]' % (m['id'], m['placard_class'],
                                                        m.get('placard_class_name') or '', m['tier'], m['assertion'])]
        out += ['  ' + line for line in wrap(m['title'], WRAP - 2)]
        if m.get('money_bound', {}).get('expression'):
            out += ['  money: ' + line for line in wrap(m['money_bound']['expression'], WRAP - 9)]
        if m.get('matched_selectors'):
            out += ['  matched: ' + line for line in wrap(' '.join(m['matched_selectors']), WRAP - 11)]
        if m.get('absent_checked'):
            out.append('  absence checks: %d' % m['absent_checked'])
    out += ['', 'NOT CHECKED']
    for item in report['not_checked']:
        out += ['  - ' + line for line in wrap(item, WRAP - 4)]
    out += ['', 'cite the placard id, the code sha256 and the register digest.']
    return out


def paginate(lines, size=MAX_LINES):
    return [lines[i:i + size] for i in range(0, len(lines), size)] or [[]]


def render_pdf(report):
    pages = paginate(lines_for(report))
    objects = []
    contents = []
    for page in pages:
        body = ['BT', '/F1 %g Tf %g TL' % (SIZE, LEADING), '%g %g Td' % (MARGIN, A4[1] - MARGIN)]
        for line in page:
            body.append('(%s) Tj T*' % escape(line))
        body.append('ET')
        contents.append('\n'.join(body).encode())
    count = len(pages)
    # 1 catalog, 2 pages, then one page + one content object per page, then the font
    font_obj = 3 + 2 * count
    kids = ' '.join('%d 0 R' % (3 + 2 * i) for i in range(count))
    objects.append(b'<< /Type /Catalog /Pages 2 0 R >>')
    objects.append(('<< /Type /Pages /Count %d /Kids [%s] >>' % (count, kids)).encode())
    for i in range(count):
        objects.append(('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] '
                        '/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>'
                        % (A4[0], A4[1], font_obj, 4 + 2 * i)).encode())
        stream = contents[i]
        objects.append(b'<< /Length %d >>\nstream\n' % len(stream) + stream + b'\nendstream')
    objects.append(b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>')

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
