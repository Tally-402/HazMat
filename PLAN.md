# HazMat build plan

Ordered by dependency. Each phase has a definition of done. Nothing ships a claim it cannot back.

## Progress

| phase | state |
|---|---|
| P0 format freeze | done |
| P1 corpus | 15 placards, 9 classes, self-check green against six controls |
| P2 engine hardening | done: require_any/require_none_of, derive.py, in-repo keccak, chain registry, batch |
| P3 confirmation runner | done: all ten placards confirmed, rebuilt selectors identical to the deployed runtime |
| P4 product surface | done: CLI, sheets with coverage and subject resolution, PDF, verify, server, front end |
| P5 watch service | done: feed poll, upgrade detection on feed and watchlist, sqlite state, alerts |
| P6 anchoring | done offline: epoch roots, proofs, on-chain verifier cross-checked |
| P7 Solana engine | deferred, trigger below |

## Standing decisions

- **EVM first, Solana second.** A corpus does not transfer between instruction sets and class authoring is the only real cost centre, so one family at a time. The schema is chain-aware from now on so the later engine does not force a format break.
- **Two tiers, enforced by CI.** `pattern` is a bytecode match and only ever a candidate. `confirmed` requires a reproduction that has run, with the command and the observed result recorded.
- **Every matcher ships with a negative control.** A placard that fires on everything proves nothing.
- **No claim of execution unless it ran.** No "audited safe", ever, from this repo.
- **Chains:** Ethereum mainnet for value and verification records, Base for volume and cheap reads. Matcher is chain-agnostic; only the RPC differs.

## P0 - format freeze

Goal: the record format cannot need a breaking change when Solana arrives.

1. Schema v2: `chain_family`, extensible `matcher.kind`, `require_any`, `require_none_of`.
2. `PLAN.md` (this file).
3. `CONTRIBUTING.md` and `templates/placard.json`.

Done when: schema validates every placard, CI rejects a confirmed placard without a reproduction, a placard for another chain family is skipped not misread.

## P1 - corpus

Goal: ten confirmed placards. Below roughly ten, a register is a demo. Reached fifteen: eleven confirmed, four pattern-tier, across nine classes and three unrelated codebases (claus-network, USDC, WETH).

1. `HZ-002`..`HZ-010` from the session findings and public post-mortems. Done.
2. A self-check harness: each placard must fire on its own target codehash and stay quiet on controls.

Done when: `matcher --self-check` passes for all placards, and each confirmed placard's command has been run and its output recorded.

## P2 - engine hardening

All four done: matcher combinators, in-repo keccak (vectors checked against known digests), chain registry, batch mode writing sheets. Stable sorted JSON throughout.

Done when: the matcher has no dependencies, runs offline against supplied code, and the CLI is scriptable.

## P3 - confirmation runner

Promote `pattern` to `confirmed` mechanically: locate verified source, build with a pinned toolchain, generate a probe from a per-class template, run it in an isolated dir, record command and observed output into the placard.

Done for all ten: each fetched from Sourcify, rebuilt with the record's own settings, rebuilt selector set identical to the deployed runtime (49/49, 59/59, 25/25, 11/11 depending on the contract), and its own probe green. Probes are per hazard and cannot be generated from a matcher alone, so each new placard ships one.

## P4 - product surface

Sheet polish, a PDF path, `hazmat verify <sheet>` to re-derive a sheet's hash, and the paste-a-CA web page.

Done when: a stranger can go address to shareable artifact without reading the repo.

## P5 - watch service

Poll new verifications and proxy upgrades, match, alert. SQLite for state, cron for cadence.

Done: a pass polls the newest verifications, inspects each, alerts on a match, and re-inspects the deployments in `register/watchlist.json` so a code change raises an `upgrade` alert. Verified live: a pass over a feed carrying the escrow alerted with HZ-001, HZ-005 and HZ-009 and wrote sheets; a real pass over 25 newly verified mainnet contracts ran clean and advanced the cursor. Still to do: give it a cadence (a scheduled pass) rather than running it by hand.

## P6 - anchoring

Merkle-root the corpus per epoch; per-match attestation on demand, so a sheet is citable and third-party verifiable.

Offline half done: epochs are merkle-rooted, a placard proves into one, a sheet names the root, and the Solidity verifier reproduces the Python prover over a generated vector (5 forge tests). Remaining: deploy `HazMatAnchor.sol` somewhere and point `hazmat verify` at it, which needs one broadcast.

## P7 - Solana engine, deferred

Trigger: 25 published EVM classes, or a paying Solana-native customer. Then: `sbf-immediate-set` matcher over `lddw` immediates, an litesvm confirmation harness, and the classes that are richer there (stranded value, upgrade lifecycle).

## Bugs found while building, and fixed on the spot

- A 40-character hex blob is exactly as long as an address, so raw code silently went to the RPC. Fixed with `--as address|code`, plus a regression test.
- `_sha256` was handed a hex string, not bytes, and crashed the supplement stage.
- A verified record can carry a *partial* remapping list, so a contract that never imported forge-std had no remapping for it and the probe could not compile. Needed remappings are now appended, never substituted.
- Cross-chain siblings: a probe on one chain may reference a contract verified on another. Extras now fall back to mainnet and record which chain each fetch used.
- A target could be given as a label rather than an address; targets are now normalised and default to the placard's own.
- Two probes referenced sibling source files the bundle cannot carry; supplements are declared per placard.
- The runner ran only the first vendored probe and ignored the placard's test selection; it now runs every vendored file under the placard's `match_test`.
- An unhandled `ConfirmError` in the compare stage lost the whole record; every stage now writes its own outcome.
- `build()` paired an unsorted level while the proof walk paired sorted ones, so proofs landed on a root the published epoch did not have. Both now share one `next_level()`, and the cross-check is a proof landing on the *published* root, not on itself. A set comprehension in the walk also deduped identical parents and halved a level twice.
- The watch feed de-duplicated against its own `seen` table, so a contract verified *again* after an upgrade was never re-inspected and the upgrade was swallowed. Candidates are now filtered by cursor only, and one `observe` path classifies each sighting as `new` or `upgrade` so neither the feed nor the watchlist can hide a change.

## Explicitly not yet

Pricing, payment plumbing, accounts, a human-review tier, insurance data products, multi-language sheets, and any claim of coverage beyond "matched against register version N".

## CI and epochs (measured, not assumed)

- `validate` runs five gates on every push: schema validation, the forge proof cross-check,
  the test suite, an offline sheet render + verify + tamper, and the self-check. It is green
  at `dd339cb`. Before that it had failed on **every push** and I had not checked: the schema
  did not know the `add_sources` key, `jsonschema` is not installed locally so the local run
  never disagreed, and forge was not installed on the runner.
- The register is therefore validated by `matcher/hazmat/schema_check.py`, a dependency-free
  validator that fails on any schema keyword it does not implement. CI and a laptop now run
  the same code, so a schema drift cannot hide behind "CI covers it".
- Publishing an epoch does not invalidate older ones. A sheet is verified against the epoch
  it names, and a proof into a closed epoch is computed from that epoch's recorded leaves,
  because today's register can no longer reproduce an old tree.

## A known-vulnerable contract, and what it taught the register

Nine mainnet contracts with documented exploits were scanned from bytecode alone (Parity
WalletLibrary, The DAO, Euler V1, Fomo3D, EtherDelta, Beanstalk, Nomad Replica, a Vyper
reentrancy pool, imBTC). **No placard fired on any of them.** That is the honest state of a
register authored from three codebases: the classic exploit classes are reentrancy, oracle
and unprotected-initialiser shaped, and a selector-set fingerprint can only speak to those
when the selector set itself encodes the hazard.

HZ-016 closes the largest of those gaps with a real precedent: an ERC777 token calls a
contract recipient back mid-transfer, so any counterparty that credits first and settles
after paying can be re-entered. imBTC was the token in the Lendf.Me drain of 2020-04-19
(~25M USD). The placard is confirmed against imBTC, byte-identical rebuild included.

Also measured: the Parity WalletLibrary has **no code at all** now - it selfdestructed in
the 2017 freeze, so `eth_getCode` returns empty and every wallet that delegatecalled it
froze. Nothing in the register speaks to "the delegatecall target is gone"; it fires
nothing there, correctly.

### Fixture lessons (solc 0.5, forge 1.8)

- `new <contract from an import>()` is rewritten by forge into a form wrapped in
  `payable(x)`, and the conversion function `payable(x)` does not exist until solc 0.6.
  With a 0.5.0 bundle the only way through is `vm.getCode` plus a bare `create`.
- The ERC1820 registry must be etched to its canonical address *before* deploying anything
  whose constructor registers itself in it, or the constructor reverts on a codeless call.
- A contract recipient of an ERC777 `send` must register an implementer, so a fixture has
  to register its actors itself - the registry requires the account to be its own manager.

### Machinery changed

- `confirm` runs against any tier now: the pipeline is the evidence and the tier is the
  claim, so a pattern placard is exactly how a claim earns `confirmed`. Previously a
  pattern placard could never be confirmed at all.
- `confirm --sync` folds records back into their placards: tier, confirmation block,
  selector agreement and probe test names, all taken from the record. Hand-written
  `equivalence` and `evidence` lines are preserved.
- Controls now include a **negative control on a famously vulnerable contract** (The DAO
  expects nothing) and imBTC (expects exactly HZ-016). Nine controls in total.
- `scripts/build-selector-index.py` rebuilds the name index from verified sources and
  merges rather than replaces, so a name never disappears when a work directory is cleaned.
