# ADR-0044: A fetch is bounded in destination, size and work

**Status:** draft · **Date:** 2026-09-17

## Context

A Publisher controls every input to an Aggregator's fetcher: the host
it names, the redirects it serves, the addresses its names resolve to,
the octets it streams and the size of its tree of files and of its Label
Feed. WIST-2 bounded two of
these — the redirect chain (§8) and a domain's daily octets (§5) — and
left the rest to the fetcher: a Declaration could aim a request at a
loopback, private or cloud-metadata address, the request-forgery class
every crawler has met; a Payload could stream without limit before its
first field check; and a single Ping could hold a pull for a whole
day's budget. Each is an amplification the protocol's own quotas do not
reach, because quotas count Pings and octets, not where a request goes
or how long one Ping's pull runs.

## Decision

- **Destinations are public unicast.** A fetch connects only to a
  public unicast address, checked on a literal host, on every redirect
  hop and on every address a name resolves to at connection time; a
  name with one refused address is refused whole. The refused classes
  are the IANA special-purpose ranges a fetcher can reach from inside a
  network — loopback, unspecified, private, link-local, shared address
  space, broadcast, multicast, documentation, benchmarking and reserved
  for IPv4; loopback, unspecified, unique local, link-local, multicast
  and documentation for IPv6 — with IPv4-mapped, 6to4 and NAT64
  addresses classified by the IPv4 address they embed. A single-machine
  deployment may admit loopback under the opt-in that admits plain HTTP.
- **Responses are bounded before their fields are.** A Declaration,
  Label Feed, Page, Mirror list or change list (ADR-0053) is read to
  1 MiB; `catalog.json` to 16 KiB
  ([ADR-0052](0052-items-and-catalogs.md)); a Label or dispute file to
  16 KiB plus twice `url_cap_bytes`; a Payload to the sum of the content
  caps plus 4 KiB. The parameterized bounds follow the caps in force at
  the request, so an amendment moves them; the fixed terms cover the
  fields no cap reaches. A tree file's own bound is the
  `tree_file_cap_bytes` in force for the request (ADR-0052): it is read
  to that bound plus one octet, and one above it refuses its Catalog and
  debits nothing, unless what remains of the budget or a per-pull octet
  limit is met first, in which case the octets read are debited and the
  walk suspends.
- **A pull may be shorter than a day's budget.** An Aggregator may
  suspend a walk under a per-pull limit of its own and resume it as a
  budget suspension; an object crossing the remaining budget or the
  limit is debited to the bound and suspends the walk, while an object
  above its own bound is a failed fetch.
- **Scope is read per request.** A redirect is checked against the
  Declaration accepted when the request is issued, so a replacement
  accepted mid-pull governs the requests after it, and before the first
  accepted Declaration a redirect stays on the requested host.

## Alternatives considered

- **Resolve once, then connect to the checked address.** Closes the
  window between check and connect that a rebinding resolver exploits,
  but binds the fetcher to one resolver answer and one address family;
  refusing a name whole when any answer is refused reaches the same
  outcome without prescribing how a client connects.
- **A Registry parameter for the flat bound.** The objects it covers are
  bounded by the schema's counts and lengths, which a parameter cannot
  move; a constant that follows the schema is simpler than a parameter
  that would have to be validated against it.
- **Bounding a Payload by `extract_cap_bytes` alone.** Rejects a Payload
  whose links and summary are full under their own caps; the bound is
  the sum of what the Payload may legitimately carry.
- **A normative per-pull limit.** The right value depends on an
  Aggregator's concurrency, not on the protocol; the decision fixes only
  that a limit is permitted and how a suspended walk resumes.

## Consequences

- Aggregators classify every destination address and cap every read;
  a Publisher behind a private or link-local address is not fetched,
  and a Publisher whose objects exceed their bounds is treated as
  unfetchable under WIST-2 §5's existing dispositions.
- `vectors/wist2/fetch-bounds.json` carries address classes, resolver
  answers, response bounds under two parameter maps, pull-work
  dispositions and a redirect sequence across two Declarations; its
  bound for a Delta file and its Label Feed cases, ordered after a Feed
  walk, describe objects WIST-2 no longer defines.
