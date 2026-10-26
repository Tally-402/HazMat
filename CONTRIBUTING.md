# Contributing a placard

1. **Reproduce it first.** A placard without a reproduction is `tier: pattern`, and CI treats it as a candidate.
2. **Give it a negative control.** Every matcher must be checked against code that should *not* fire. A matcher that matches everything proves nothing.
3. **Bound the money.** `money_bound.kind` is one of `none`, `per-event`, `per-deal`, `capacity`, `capability`, and `expression` says what is moved.
4. **Pick the lowest class that is true.** Classes 1-9 are listed in the README; a hazard gets one class, not the scariest one.
5. **Cite provenance.** Specimen commit, published source path with lines, and the deployed target if there is one.

## Before pushing

    cd matcher && python -m unittest discover -s tests
    python -m hazmat.match --register register/placards --code <target code hash>

`require_none_of` is an absence check over the exact signatures listed. It does not prove a function does not exist under another name; say so in `matcher.notes`.

## Barriers

- `pattern` never becomes `confirmed` by wording. It becomes confirmed when the command runs and the output is recorded in `confirmed_on`.
- A placard that only fires on one instance stays in the register, but the `notes` must say so.
