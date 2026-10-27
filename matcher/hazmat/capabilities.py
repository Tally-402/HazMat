"""Answer the questions a person actually asks, from the selectors the code exposes.

A placard says what is dangerous. This says what the contract *is* and what whoever runs it
can do to you: can the rules change, can your tokens be frozen, can the supply be inflated,
who is in charge, can they take the money. Every answer is a fingerprint - selectors present
in the runtime - and every answer states what it cannot tell you.

Nothing here is a clearance. It is the shape of the contract in plain words.
"""
from . import keccak


def sig(text):
    return '0x' + keccak.selector_hex(text), text


def _bits(*texts):
    return [sig(t) for t in texts]


TOKEN = _bits('totalSupply()', 'balanceOf(address)', 'transfer(address,uint256)')
ALLOWANCES = _bits('approve(address,uint256)', 'transferFrom(address,address,uint256)', 'allowance(address,address)')
VAULT = _bits('deposit()', 'withdraw(uint256)')
UPGRADE = _bits('upgradeTo(address)', 'upgradeToAndCall(address,bytes)', 'implementation()', 'admin()', 'proxiableUUID()')
FREEZE = _bits('pause()', 'unpause()', 'paused()')
DENY = _bits('isBlacklisted(address)', 'blacklist(address)')
SWITCH = _bits('disableTransfer()', 'enableTransfer()', 'transferable()')
MINT = _bits('mint(uint256)', 'mint(address,uint256)', 'mint(address,uint256,bytes,bytes)', 'isMinter(address)', 'addMinter(address)')
OWNER = _bits('owner()', 'transferOwnership(address)', 'isOwner()', 'admin()')
TWO_STEP = _bits('acceptOwnership()', 'pendingOwner()')
SWEEP = _bits('sweep(address)', 'rescue(address,uint256)', 'distributeRevenue()', 'setRevenueAddress(address)', 'collectFees()')
PERMIT = _bits('permit(address,address,uint256,uint256,uint8,bytes32,bytes32)', 'nonces(address)')
HOOKS = _bits('granularity()', 'defaultOperators()', 'send(address,uint256,bytes)')
INIT = _bits('initialize()', 'initialize(address)', 'initialized()', 'isInitialized()')
BATCH = _bits('safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)', 'setApprovalForAll(address,bool)')

# question, then why it fires, then the plain answer, then what it cannot tell you
PROBES = [
    {'id': 'shape',
     'question': 'What is this?',
     'when': {'always': True},
     'answer': 'It is {shape}. Everything below is read from the bytecode it exposes, not from its docs.',
     'cannot': 'Whether it is any good, and who wrote it.'},
    {'id': 'upgrade',
     'related': ['HZ-011', 'HZ-012'],
     'question': 'Can the rules change under me?',
     'when': {'any': UPGRADE, 'or_kind': ('proxy', 'possible-proxy')},
     'answer': 'Yes. This is a proxy or it exposes upgrade entry points, so the code that runs can be '
               'replaced while the address, and anything you have deposited, stays put. The rules you read '
               'today are not guaranteed to be the rules tomorrow.',
     'cannot': 'Who holds the upgrade key, and whether there is a delay before a change takes effect.'},
    {'id': 'freeze',
     'related': ['HZ-013'],
     'question': 'Can they freeze or block my tokens?',
     'when': {'any': FREEZE},
     'answer': 'Yes, transfers can be paused: the contract carries pause/unpause, so a holder of that key '
               'can stop everyone moving tokens, including you.',
     'cannot': 'Who holds the pause key, and whether the pause affects withdrawals too.'},
    {'id': 'deny',
     'related': ['HZ-014'],
     'question': 'Can my address be singled out?',
     'when': {'any': DENY},
     'answer': 'Yes. There is a deny list: an operator can mark an address and its balance stops moving, '
               'so being on the wrong side of that list is a real risk, not a theoretical one.',
     'cannot': 'Who can edit the list, or on what policy.'},
    {'id': 'switch',
     'question': 'Can transfers be switched off entirely?',
     'when': {'any': SWITCH},
     'answer': 'Yes. Transfers can be turned on and off as a switch, which is how some tokens spend their '
               'first days restricted to a whitelist.',
     'cannot': 'Whether it is currently on, and who can flip it.'},
    {'id': 'mint',
     'question': 'Is the supply fixed?',
     'when': {'any': MINT},
     'answer': 'No. The supply can be minted, so what you hold is a share of something that can grow. '
               'Minting is not inherently bad; unminted-and-unbounded is what dilutes you.',
     'cannot': 'Whether there is a cap, and who holds the mint key.'},
    {'id': 'owner',
     'question': 'Who is in charge?',
     'when': {'any': OWNER},
     'answer': 'A single address holds admin rights, {two_step}, and that address is not visible from '
               'bytecode at all.',
     'cannot': 'Whether that address is an EOA, a multisig or a timelock. Check it before trusting the admin.'},
    {'id': 'no_owner',
     'question': 'Who is in charge?',
     'when': {'none': OWNER},
     'answer': 'No owner or admin function is exposed here. Either nothing is configurable, or the power sits '
               'behind a proxy or another contract this scan could not follow.',
     'cannot': 'Which of those two it is.'},
    {'id': 'sweep',
     'related': ['HZ-005'],
     'question': 'Can whoever runs it take the money?',
     'when': {'any': SWEEP},
     'answer': 'Partly, and on purpose: there are admin paths to move value out (a sweep, a rescue, or a '
               'revenue redirect). They usually cannot touch your balance directly, but they can change where '
               'the money goes.',
     'cannot': 'Whether those paths can reach your funds or only the contract\'s own leftovers.'},
    {'id': 'allowances',
     'question': 'Can anyone else move my balance?',
     'when': {'any': ALLOWANCES},
     'answer': 'Only with your approval: this is an allowance-based token, so the standing risk is what you '
               'have approved, not what the contract can do on its own.',
     'cannot': 'What you have approved right now - that is state, not bytecode.'},
    {'id': 'permit',
     'question': 'Can an approval be made without a transaction?',
     'when': {'any': PERMIT},
     'answer': 'Yes, there is permit(): an approval can be granted by a signature, so someone can be given '
               'spending rights with no on-chain transaction from you. Convenient, and worth watching.',
     'cannot': 'Whether any signature you have already made is still unused (nonces are state).'},
    {'id': 'hooks',
     'related': ['HZ-016'],
     'question': 'What happens when a transfer lands?',
     'when': {'any': HOOKS},
     'answer': 'The recipient is called back mid-transfer, before the transfer returns. That is what makes a '
               'counterparty that credits first and settles after paying re-enterable - the shape of the '
               'Lendf.Me drain.',
     'cannot': 'Whether any particular pool or vault you use is written safely. That is its own scan.'},
    {'id': 'init',
     'question': 'Could someone initialise it first?',
     'when': {'any': INIT},
     'answer': 'There is an initializer, so the state is set by whoever calls it. An initializer left open on '
               'a live contract is a takeover, not a formality.',
     'cannot': 'Whether it has already been called, and by whom.'},
    {'id': 'batch',
     'question': 'Is this an NFT or multi-token contract?',
     'when': {'any': BATCH},
     'answer': 'Yes. Multi-token shape: approvals are per-operator rather than per-token, so one approval can '
               'cover a whole collection.',
     'cannot': 'Collection-wide policy, which lives off chain.'},
]


def spoken(pair):
    return '%s %s' % (pair[0], pair[1]) if pair[0].startswith('0x') else pair[1]


def shape_of(report, present):
    kind = ((report.get('subject') or {}).get('kind') or '')
    identity = [v.get('name') for v in (((report.get('subject') or {}).get('identity')) or {}).values()
                if v.get('name')]
    if kind in ('proxy', 'possible-proxy'):
        return 'a proxy: calls are forwarded to logic held at another address'
    if all(pair[0] in present for pair in TOKEN):
        return 'a token contract%s' % (' verified as %s' % identity[0] if identity else '')
    if any(pair[0] in present for pair in VAULT):
        return 'a contract that takes deposits%s' % (' verified as %s' % identity[0] if identity else '')
    return 'a contract%s on %s' % (' verified as %s' % identity[0] if identity else '',
                                   ((report.get('subject') or {}).get('chain') or report.get('chain') or 'chain unstated'))


def fired(probe, present, kind):
    """Does this probe apply, and on what evidence? Kind-based probes carry their own note."""
    when = probe['when']
    if when.get('always'):
        return True, []
    if 'none' in when:
        return not any(pair[0] in present for pair in when['none']), []
    seen = [pair for pair in when.get('any', []) if pair[0] in present]
    if seen:
        return True, seen[:3]
    if when.get('or_kind') and kind in when['or_kind']:
        return True, [('kind', 'the scan resolved this as a %s' % kind)]
    return False, []


def answers(report, limit=None):
    """Fire the probes the code justifies, in the order a person would ask them."""
    present = set((report.get('coverage') or {}).get('selectors_present') or [])
    kind = ((report.get('subject') or {}).get('kind') or '')
    out = []
    for probe in PROBES:
        ok, seen = fired(probe, present, kind)
        if not ok:
            continue
        answer = probe['answer']
        if '{shape}' in answer:
            answer = answer.replace('{shape}', shape_of(report, present))
        if '{two_step}' in answer:
            two_step = any(pair[0] in present for pair in TWO_STEP)
            answer = answer.replace('{two_step}', 'and the handover takes two steps, which is the safer version'
                                    if two_step else 'and the handover is a single transaction')
        out.append({'id': probe['id'], 'question': probe['question'], 'answer': answer,
                    'cannot': probe['cannot'], 'related': probe.get('related', []),
                    'evidence': [spoken(pair) for pair in seen]})
    if limit:
        out = out[:limit]
    return out


def what_to_check(report):
    """The plain-English checklist: the fixes for what matched, plus the shape warnings."""
    checks = []
    for match in report.get('matches') or []:
        fix = (match.get('fix') or '').strip()
        if fix and fix not in checks:
            checks.append(fix)
    kind = ((report.get('subject') or {}).get('kind') or '')
    if kind in ('proxy', 'possible-proxy'):
        checks.append('Find out who can upgrade it, and whether there is a delay.')
    if any(a['id'] == 'owner' for a in answers(report)):
        checks.append('Find out what the owner address actually is: an EOA, a multisig or a timelock.')
    return checks[:5]


def bottom_line(report):
    """One honest sentence a person can act on."""
    matches = report.get('matches') or []
    total = report.get('register_size', 0)
    if not matches:
        return ('Nothing in this register matched, so it is unfamiliar rather than cleared. %d hazards were '
                'checked; the ones that fired nowhere include reentrancy, ordering and authority shapes. '
                'Nothing here says safe.' % total)
    ids = ', '.join(m['id'] for m in matches[:3])
    return ('%d of %d registered hazards are present (%s). That is the fingerprint, not a verdict: somebody '
            'still has to read the code, and %s' % (len(matches), total, ids,
            'the sharpest one has already been reproduced against this very contract, which raises it from '
            'a shape to a demonstrated behaviour.' if any((m.get('confirmed_on') or []) for m in matches)
            else 'none of them has been reproduced here, so they are shapes until somebody runs them.'))
