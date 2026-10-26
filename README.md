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

## Confirming a placard

A `confirmed` placard can be re-confirmed from scratch: source is fetched from Sourcify, rebuilt with the settings from the verification record, compared selector-for-selector against the deployed runtime, then its vendored reproduction is run against the rebuild.

    python3 -m hazmat.confirm --placard HZ-001 --target 0xc2292af8B51109a27A4B4e28E9cF9f3AeDE4190C --chain mainnet \
        --forge-std path/to/forge-std --lib openzeppelin-contracts=path/to/openzeppelin-contracts

The record lands in `confirmations/`, one per placard and target, with every stage's own outcome. Verdicts: `confirmed`, `confirmed_with_selector_drift`, `refuted`, `blocked`. A probe that runs and fails is `refuted`, and an earlier stage failing is `blocked` - never silently confirmed.

## Contributing a placard

1. Reproduce the hazard and keep the repro runnable.
2. Write the placard, `tier: confirmed` only if the repro runs.
3. `cd matcher && python -m unittest discover -s tests`.

## Licence

Code MIT. Placards CC-BY-4.0: cite the id, the target code hash and the register size.

## Status

Ten placards across seven classes, a working matcher, selector derivation from source and ABI, and a self-check where every listed target is a negative control for every placard it does not expect. No anchoring yet.
