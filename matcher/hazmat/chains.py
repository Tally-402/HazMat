"""Chain registry: a name resolves to a public read endpoint.

One chain per entry is enough to read code, which is all the matcher needs.
"""
CHAINS = {
    'mainnet': {'chain_id': 1, 'rpc': 'https://ethereum-rpc.publicnode.com'},
    'base': {'chain_id': 8453, 'rpc': 'https://base-rpc.publicnode.com'},
    'arbitrum': {'chain_id': 42161, 'rpc': 'https://arbitrum-one-rpc.publicnode.com'},
    'optimism': {'chain_id': 10, 'rpc': 'https://optimism-rpc.publicnode.com'},
    'sepolia': {'chain_id': 11155111, 'rpc': 'https://ethereum-sepolia-rpc.publicnode.com'},
}
DEFAULT = 'mainnet'


def endpoint(name):
    if name not in CHAINS:
        raise KeyError('unknown chain: %s (known: %s)' % (name, ', '.join(sorted(CHAINS))))
    return CHAINS[name]['rpc']


def chain_id(name):
    return CHAINS[name]['chain_id']


def label(name):
    return '%s (chainId %d)' % (name, CHAINS[name]['chain_id'])
