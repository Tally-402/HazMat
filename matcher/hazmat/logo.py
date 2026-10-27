"""Decode the committed mark, so the PDF can carry it.

The asset is our own file: 8-bit RGBA, non-interlaced. Transparency is composited onto white,
which is what a page is, so the PDF needs no soft mask.
"""
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MARK = ROOT / 'web' / 'logo.png'


def pixels(path=None, background=(255, 255, 255)):
    """Return (width, height, rgb bytes), alpha flattened onto the background."""
    raw = Path(path or MARK).read_bytes()
    if raw[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('not a png')
    pos, idat, header = 8, b'', None
    while pos < len(raw):
        length = struct.unpack('>I', raw[pos:pos + 4])[0]
        kind = raw[pos + 4:pos + 8]
        if kind == b'IHDR':
            header = struct.unpack('>IIBBBBB', raw[pos + 8:pos + 21])
        elif kind == b'IDAT':
            idat += raw[pos + 8:pos + 8 + length]
        elif kind == b'IEND':
            break
        pos += 12 + length
    width, height, depth, colour, _, _, interlace = header
    if depth != 8 or interlace != 0:
        raise ValueError('unsupported png: depth %s interlace %s' % (depth, interlace))
    bpp = {0: 1, 2: 3, 4: 2, 6: 4}[colour]
    stride = width * bpp
    data = zlib.decompress(idat)
    flat, previous, index = bytearray(), bytearray(stride), 0
    for _ in range(height):
        method = data[index]
        index += 1
        line = bytearray(data[index:index + stride])
        index += stride
        for x in range(stride):
            left = line[x - bpp] if x >= bpp else 0
            up = previous[x]
            corner = previous[x - bpp] if x >= bpp else 0
            if method == 1:
                line[x] = (line[x] + left) & 255
            elif method == 2:
                line[x] = (line[x] + up) & 255
            elif method == 3:
                line[x] = (line[x] + ((left + up) >> 1)) & 255
            elif method == 4:
                estimate = left + up - corner
                pa, pb, pc = abs(estimate - left), abs(estimate - up), abs(estimate - corner)
                nearest = left if (pa <= pb and pa <= pc) else (up if pb <= pc else corner)
                line[x] = (line[x] + nearest) & 255
        flat += line
        previous = line
    rgb = bytearray()
    for y in range(height):
        for x in range(width):
            offset = (y * width + x) * bpp
            pixel = flat[offset:offset + bpp]
            if bpp == 4:
                alpha = pixel[3]
                rgb += bytes([(pixel[channel] * alpha + background[channel] * (255 - alpha)) // 255
                              for channel in range(3)])
            elif bpp == 3:
                rgb += pixel
            else:
                value = pixel[0]
                rgb += bytes((value, value, value))
    return width, height, bytes(rgb)
