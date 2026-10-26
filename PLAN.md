# HazMat build plan

Ordered by dependency. Each phase has a definition of done. Nothing ships a claim it cannot back.

## Progress

| phase | state |
|---|---|
| P0 format freeze | done |
| P1 corpus | 5 of 10 placards, self-check green |
| P2 engine hardening | partially done: derive.py, require_none_of, family gate |
| P3 confirmation runner | not started |
| P4 product surface | not started |
| P5 watch service | not started |
| P6 anchoring | not started |
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

Goal: ten confirmed placards. Below roughly ten, a register is a demo.

1. `HZ-002`..`HZ-009` from the session findings and public post-mortems.
2. A self-check harness: each placard must fire on its own target codehash and stay quiet on controls.

Done when: `matcher --self-check` passes for all placards, and each confirmed placard's command has been run and its output recorded.

## P2 - engine hardening

1. `require_none_of` and `require_any` in the matcher.
2. In-repo keccak so selectors are derived, not hardcoded.
3. Chain registry (mainnet, base) with endpoint fallback.
4. `hazmat scan`, `hazmat batch --file`, stable sorted JSON.

Done when: the matcher has no dependencies, runs offline against supplied code, and the CLI is scriptable.

## P3 - confirmation runner

Promote `pattern` to `confirmed` mechanically: locate verified source, build with a pinned toolchain, generate a probe from a per-class template, run it in an isolated dir, record command and observed output into the placard.

Done when: `HZ-001` confirms against a fresh clone with no hand-holding.

## P4 - product surface

Sheet polish, a PDF path, `hazmat verify <sheet>` to re-derive a sheet's hash, and the paste-a-CA web page.

Done when: a stranger can go address to shareable artifact without reading the repo.

## P5 - watch service

Poll new verifications and proxy upgrades, match, alert. SQLite for state, cron for cadence.

Done when: a new deployment matching a placard produces an alert without human action.

## P6 - anchoring

Merkle-root the corpus per epoch; per-match attestation on demand, so a sheet is citable and third-party verifiable.

Done when: a sheet's hash resolves on-chain against a corpus root.

## P7 - Solana engine, deferred

Trigger: 25 published EVM classes, or a paying Solana-native customer. Then: `sbf-immediate-set` matcher over `lddw` immediates, an litesvm confirmation harness, and the classes that are richer there (stranded value, upgrade lifecycle).

## Explicitly not yet

Pricing, payment plumbing, accounts, a human-review tier, insurance data products, multi-language sheets, and any claim of coverage beyond "matched against register version N".
