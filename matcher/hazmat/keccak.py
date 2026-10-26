"""Keccak-256 in pure Python, so selector work never needs a cast binary.

Note the padding byte: Keccak uses 0x01 where SHA3 uses 0x06. Ethereum is Keccak.
"""
MASK = (1 << 64) - 1
RATE = 136
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]


def _rotl(value, n):
    return ((value << n) | (value >> (64 - n))) & MASK if n else value


def _permute(state):
    for rnd in range(24):
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & MASK & b[(x + 2) % 5 + 5 * y] & MASK)
        state[0] ^= RC[rnd]


def keccak256(data):
    if isinstance(data, str):
        data = data.encode()
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % RATE != RATE - 1:
        padded.append(0x00)
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), RATE):
        block = padded[offset:offset + RATE]
        for i in range(RATE // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], 'little')
        _permute(state)
    out = bytearray()
    while len(out) < 32:
        for i in range(RATE // 8):
            out += state[i].to_bytes(8, 'little')
            if len(out) >= 32:
                break
        if len(out) < 32:
            _permute(state)
    return bytes(out[:32])


def selector(signature):
    """Four-byte selector for an ABI signature, as 0x-hex."""
    return '0x' + keccak256(signature)[:4].hex()


def selector_hex(signature):
    return keccak256(signature)[:4].hex()
