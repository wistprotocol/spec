# ADR-0014: The Canonical Host flag profile, and no lowercasing before it

**Status:** accepted · amended by ADR-0017 (2026-09-04: the Unicode version is pinned alongside the flags) · **Date:** 2026-08-16

## Context

The Canonical Host is the identity surface of this suite. It is the
Publisher's name in a Declaration, the authority a Delta's `url` is scoped
against (WIST-1 §3.2), the key of a Record tuple and therefore an input to
`content_digest` (WIST-3 §7), and the comparison WIST-2 §11 applies to every
link target when it decides which citations are internal and which reach
another domain. A host the suite cannot canonicalize is not merely a
Publisher who cannot join: it is a citation every Consumer silently drops.

WIST-1 §2 pinned UTS #46 processing with `UseSTD3ASCIIRules=true`,
`Transitional_Processing=false` and `VerifyDnsLength=true`, and said the
input is "a hostname lowercased". Three UTS #46 flags were left unstated —
`CheckHyphens`, `CheckBidi`, `CheckJoiners` — and the lowercasing step named
no case operation.

Both gaps have observable consequences. An implementation reaching for a
strict default (Rust's `idna::domain_to_ascii_strict`, for instance) gets
`CheckHyphens=true`, which rejects any label with hyphens in the third and
fourth positions — the shape CDN nodes such as `r2---sn-x.example` actually
use, and which every browser resolves. And "lowercased" admits a
context-sensitive full lowercase, which maps a word-final Σ to ς where UTS
#46's own mapping step maps it to σ: the same input then yields
`xn--mxa8a` or `xn--mxa0b` depending on which implementation canonicalized
it. §2's stated purpose is to prevent exactly that, and its rationale
paragraph cites final sigma by name.

## Decision

**The flag profile is the browser profile, plus this suite's existing
strictness.** WIST-1 §2 now pins all six flags:
`UseSTD3ASCIIRules=true`, `CheckHyphens=false`, `CheckBidi=true`,
`CheckJoiners=true`, `Transitional_Processing=false`,
`VerifyDnsLength=true`.

`CheckHyphens=false` matches what the WHATWG URL Standard applies, on the
grounds that hyphen position inside a label is registry policy rather than
identity. `CheckBidi` and `CheckJoiners` stay on, because those rules govern
visual confusability, which is the attack a domain-anchored identity is
exposed to. `UseSTD3ASCIIRules` and `VerifyDnsLength` stay stricter than the
browser profile, as they already were: those bound what the DNS itself will
carry.

**No lowercasing precedes the mapping.** UTS #46's mapping step is the case
operation, and §2 now forbids any case operation in front of it.

`vectors/wist1/host-canonicalization.json` carries the discriminating cases,
including the sigma case whose two possible A-labels this decision chooses
between.

## Alternatives considered

**All three checks on.** The strictest reading, and the one an
implementation falls into by using a library's "strict" entry point. It was
rejected because it excludes hosts that resolve and serve today, and the
exclusion is not confined to those hosts: their inbound citations vanish
from every Consumer's link graph, degrading a dataset that did nothing
wrong. It is also the harder direction to leave — loosening later changes
canonicalization output for hosts already sealed into Logs.

**All three off.** Maximum acceptance, and closest to a browser's own
address bar. Rejected because dropping `CheckBidi` and `CheckJoiners` makes
visually confusable labels distinct Publisher identities, in a model where
the domain *is* the identity.

**Pinning the lowercase step to ASCII-only.** Correct and easy to
implement, but it keeps a stage whose only remaining job is one UTS #46
already performs, and every additional stage in an identity computation is
another place two implementations can differ.

## Consequences

- Canonical Host is computable by a single call into any conforming UTS #46
  implementation with three arguments, and no pre-processing.
- Hosts using positional hyphens become valid Publishers and valid link
  targets. No host that was valid before becomes invalid.
- The final-sigma case has one answer, and it is the one §2's rationale
  always implied.
- The profile is not the most permissive available, and the two flags kept
  on are kept on for a stated reason, so a future proposal to relax them has
  something to argue against.
