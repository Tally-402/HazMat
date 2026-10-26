# HazMat

An open register of **bytecode hazards** for smart contracts, with placards, safety data sheets and verifiable attestations.

A hazard should be recorded once and matched everywhere. HazMat keys a hazard to a **bytecode fingerprint**, not to a project name, so one discovery maps onto every contract that shares the pattern - including unverified ones, and including proxy implementations.

    hazmat match --code 0xc2292af8b51109a27a4b4e28e9cf9f3aede4190c

## Two tiers, and the difference is the point

| tier | meaning |
|---|---|
| `pattern` | a bytecode match. Cheap, deterministic, needs no source. Still only a candidate. |
| `confirmed` | the placard ships a reproduction that has been executed, with a money bound. |

A match is never reported as safe. Every sheet lists what was **not** checked.

## Placard classes

| class | failure mode |
|---|---|
| 1 | extraction |
| 2 | ordering |
| 3 | authority |
| 4 | availability |
| 5 | encoding |
| 6 | asset handling |
| 7 | stranded value |
| 8 | upgrade lifecycle |
| 9 | lifecycle state |

## The register

`register/placards/HZ-001.json` and onward, append-only, never renumbered, cited like a CVE. `HZ-001` is the first: *a still-valid action is destroyed by a permissionless trigger in the same block*, confirmed on a deployed mainnet escrow whose published source was verified byte-identical to the live runtime.

Every placard carries an id, class, matcher, money bound, reproduction, fix, provenance and author. Confirmed placards must ship a runnable reproduction - CI enforces it.

## Layout

    register/schema/     JSON Schema for a placard
    register/placards/   one signed record per hazard, append-only
    matcher/hazmat/      matcher (no dependencies) and the safety data sheet renderer
    matcher/tests/       matcher tests

## Matching

    python3 -m hazmat.match --register register/placards --code 0xHEX
    python3 -m hazmat.match --register register/placards --code 0xADDRESS --rpc https://...

Input is raw code, a file, or an address. Metadata is excluded by its length field; four-byte constants are extracted with correct push-data stepping. Output is JSON, and the sheet is the artifact you hand to someone.

## Deriving selectors

Hand-writing selectors is guessing. Derive them from source, then check membership against the runtime code:

    python3 -m hazmat.derive path/to/src --address 0x... --rpc https://...

Only a selector reported `PRESENT` belongs in `require_all`. Struct parameters are expanded to their tuple form, which is also how two ABIs of the same family are told apart in bytecode.

## Self-check

Every placard must fire on its own target and stay quiet on the others. Each listed address is a negative control for every placard it does not expect:

    python3 -m hazmat.selfcheck

## Batch and chains

    python3 -m hazmat.batch --file targets.txt --chain mainnet --sheet-dir sheets/

One line per target: an address, raw code, or a path. Chains are named (`mainnet`, `base`, `arbitrum`, `optimism`, `sepolia`); `--rpc` overrides.

Keccak-256 is implemented in-repo, so the matcher and the deriver have no dependencies at all and no `cast` binary is needed.

A 40-character hex string is ambiguous: exactly an address, and also a plausible 20-byte code blob. `--as address` or `--as code` settles it; the default prefers the address and says so loudly when the chain has nothing there.

## What a scan returns

A sheet, self-contained HTML with its own digest, plus the same content as JSON and as a PDF written by a dependency-free writer in this repo:

    hazmat scan --code 0xADDRESS --chain mainnet --sheet out.html --pdf out.pdf
    hazmat verify --sheet out.html              # re-derive the digest; non-zero if it was altered

An example lives in `examples/` (sheet digest `0x01b80630011c7f35fd21e1ebab6e54db22e9ee79fac50cd5eeb05b72168355f4`), scanned from the live mainnet escrow.

## Watch

    hazmat watch once --chain mainnet --sheet-dir sheets/     # one pass, cron-shaped
    hazmat watch run  --chain mainnet --interval 300          # loop
    hazmat watch status                                        # counters, cursor, recent alerts

A pass polls the newest verified contracts, inspects each one, and alerts when a placard matches. `register/watchlist.json` names live deployments to re-inspect every pass, so a code change there raises an `upgrade` alert. State is sqlite, alerts are JSONL, and a webhook is posted to only if `--webhook` or `HAZMAT_WEBHOOK` is set. Read-only throughout.

Expect a pass over the wider world to be quiet: the register is ten placards and they are shaped after one project, so breadth is what the register is now short of.

## Scheduling it

`scripts/watch-pass.py` is the scheduled form: one pass, printing only when something matched, changed or errored, so a quiet tick is silent. Hermes cron runs scripts from `~/.hermes/scripts/`, so a two-line wrapper named `hazmat-watch-pass.py` there calls it by path and keeps this file the single source of truth.

## Serve it

    hazmat serve --port 8712

`/` is a paste-a-target form, `/scan` is JSON, `/sheet` is HTML, `/pdf` is a PDF. Standard library only, read-only, and every response carries the code digest.

## Anchors

The register is merkle-rooted per epoch, so a sheet names the root it was matched against and a single placard can be proved into it without republishing the corpus.

    hazmat anchor root --epoch 1        # writes anchors/epoch-1.json
    hazmat anchor prove --placard HZ-001  # leaf + siblings + root
    hazmat anchor verify --proof proof.json

Rules are frozen in `matcher/hazmat/anchor.py`: leaf is `keccak256` of the placard's canonical json, so reformatting a file does not move a root while changing a field does; every pair is sorted before hashing so a proof needs no side flags; an odd level sorts first and then duplicates its last node. `anchors/HazMatAnchor.sol` implements the same fold on-chain, and `scripts/anchor-forge-test.sh` checks the Solidity verifier against the Python prover over a generated vector, so the two cannot drift. Not deployed yet.

## Confirming a placard

A `confirmed` placard can be re-confirmed from scratch: source is fetched from Sourcify, rebuilt with the settings from the verification record, compared selector-for-selector against the deployed runtime, then its vendored reproduction is run against the rebuild.

    python3 -m hazmat.confirm --placard HZ-001 --target 0xc2292af8B51109a27A4B4e28E9cF9f3AeDE4190C --chain mainnet \
        --forge-std path/to/forge-std --lib openzeppelin-contracts=path/to/openzeppelin-contracts

No flags are required: forge, solc, forge-std, OpenZeppelin and the upstream source tree are discovered, and every path used is written into the record. Override with `--forge`, `--forge-std`, `--lib NAME=PATH`, `--source-root` or `HazMat`'s `HAZMAT_LIBS="name=/path:..."`.

The record lands in `confirmations/`, one per placard and target, with every stage's own outcome. Verdicts: `confirmed`, `confirmed_with_selector_drift`, `refuted`, `blocked`. A probe that runs and fails is `refuted`, and an earlier stage failing is `blocked` - never silently confirmed. A file the verified bundle already carries is never overwritten by a supplement or a library: the bundle stays authoritative.

## Contributing a placard

1. Reproduce the hazard and keep the repro runnable.
2. Write the placard, `tier: confirmed` only if the repro runs.
3. `cd matcher && python -m unittest discover -s tests`.

## Licence

Code MIT. Placards CC-BY-4.0: cite the id, the target code hash and the register size.

## Status

Ten placards across seven classes, a working matcher, selector derivation from source and ABI, and a self-check where every listed target is a negative control for every placard it does not expect. No anchoring yet.
