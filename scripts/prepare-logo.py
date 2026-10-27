#!/usr/bin/env python3
"""Turn the source logo into a small transparent mark, with no image library.

The source is a 1254x1254 RGB PNG: a charcoal figure on a light grey field, hard-edged and
flat, so it quantises to two tones cleanly. Background and light cut-outs become transparent
(so the mark works on a dark header behind a light chip, and on a white page), and the whole
thing is nearest-neighbour downscaled to 128px - an exact divisor of the header and sheet
sizes, so the pixel grid stays square.
"""
import argparse
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = 64          # the source is ~64px art upscaled, so this is its native size
INK = (0x3a, 0x3a, 0x3a)
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def read_png(path):
    raw = Path(path).read_bytes()
    if raw[:8] != b'\x89PNG\r\n\x1a\n':
        raise SystemExit('not a png: %s' % path)
    pos, idat, header = 8, b'', None
    while pos < len(raw):
        length = struct.unpack('>I', raw[pos:pos + 4])[0]
        kind = raw[pos + 4:pos + 8]
        body = raw[pos + 8:pos + 8 + length]
        if kind == b'IHDR':
            header = struct.unpack('>IIBBBBB', body)
        elif kind == b'IDAT':
            idat += body
        pos += 12 + length
    width, height, depth, colour, _, _, interlace = header
    if depth != 8 or interlace != 0:
        raise SystemExit('only 8-bit non-interlaced is supported')
    bpp = CHANNELS[colour]
    stride = width * bpp
    data = zlib.decompress(idat)
    out, previous, index = bytearray(), bytearray(stride), 0
    for _ in range(height):
        method = data[index]
        index += 1
        line = bytearray(data[index:index + stride])
        index += stride
        if method == 1:
            for x in range(bpp, stride):
                line[x] = (line[x] + line[x - bpp]) & 255
        elif method == 2:
            for x in range(stride):
                line[x] = (line[x] + previous[x]) & 255
        elif method == 3:
            for x in range(stride):
                left = line[x - bpp] if x >= bpp else 0
                line[x] = (line[x] + ((left + previous[x]) >> 1)) & 255
        elif method == 4:
            for x in range(stride):
                left = line[x - bpp] if x >= bpp else 0
                up, upleft = previous[x], previous[x - bpp] if x >= bpp else 0
                estimate = left + up - upleft
                pa, pb, pc = abs(estimate - left), abs(estimate - up), abs(estimate - upleft)
                nearest = left if (pa <= pb and pa <= pc) else (up if pb <= pc else upleft)
                line[x] = (line[x] + nearest) & 255
        out += line
        previous = line
    return width, height, bpp, bytes(out)


def write_png(path, width, height, rgba):
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        raw += rgba[y * width * 4:(y + 1) * width * 4]

    def chunk(kind, body):
        return (struct.pack('>I', len(body)) + kind + body
                + struct.pack('>I', zlib.crc32(kind + body) & 0xffffffff))

    header = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    Path(path).write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header)
                           + chunk(b'IDAT', zlib.compress(bytes(raw), 9)) + chunk(b'IEND', b''))


def main():
    parser = argparse.ArgumentParser(prog='prepare-logo')
    parser.add_argument('source')
    parser.add_argument('--out', default=str(ROOT / 'web' / 'logo.png'))
    parser.add_argument('--size', type=int, default=TARGET)
    args = parser.parse_args()
    width, height, bpp, pixels = read_png(args.source)
    corner = pixels[:3]
    # the field is light and flat: anything near it, or lighter than the midpoint between it
    # and the figure, becomes transparent. That keeps the light cut-outs of the figure as holes.
    luma = [0.299 * pixels[i] + 0.587 * pixels[i + 1] + 0.114 * pixels[i + 2]
            for i in range(0, len(pixels), bpp)]
    field = luma[0]
    span = field - min(luma)
    cut = field - span * 0.45
    size = args.size
    # one ink colour for the whole mark: the median of the dark pixels, so the source's
    # resampling grey never reaches the asset
    # a fixed charcoal ink rather than the source's median grey: the mark has to read on a
    # light chip at 32px, and the source's #4d4d4d was the flattest part of the palette
    ink = INK
    rgba = bytearray()
    opaque = 0
    for y in range(size):
        source_y = min(height - 1, int((y + 0.5) * height / size))
        for x in range(size):
            source_x = min(width - 1, int((x + 0.5) * width / size))
            offset = (source_y * width + source_x) * bpp
            value = luma[(source_y * width + source_x)]
            if value >= cut:
                rgba += bytes((0, 0, 0, 0))
            else:
                rgba += bytes(ink) + bytes((255,))       # one ink, hard alpha: it is pixel art
                opaque += 1
    write_png(args.out, size, size, bytes(rgba))
    print('%s: %dx%d from %dx%d, field #%s, cut at luma %.0f, %d%% opaque, %d bytes'
          % (args.out, size, size, width, height, corner.hex(), cut,
             100 * opaque // (size * size), Path(args.out).stat().st_size))


if __name__ == '__main__':
    sys.exit(main())
