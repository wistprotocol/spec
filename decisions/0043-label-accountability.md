# ADR-0043: Labels expire, bind, are defined, are disputed and are bounded

**Status:** draft · **Date:** 2026-09-17

## Context

ADR-0041 made Labels the suite's only statement about another party:
signed, sealed, carried to every Consumer, applied only by Consumers
that subscribe. As first specified a Label had no end, no scope
narrower than a URL, no stated strength, no answer path and no bound
beyond the per-domain Epoch capacity every publication shares. Systems
with that shape have failed in known ways. A moderation labeler at
scale received two hundred thousand appeals in a year through a tool
that treated an appeal as one more report; shared blocklists in
federated networks circulate without receipts or a path for the listed
party to answer; the SKS keyserver network died in 2019 when unbounded
third-party attestations on an undeletable store made records
unusable. Each failure is a missing bound: on how long a statement
lasts, on what it covers, on how it is meant, on who can answer, and
on how much one party can say.

## Decision

- **A Label can expire.** An OPTIONAL `expires_at`, a Publisher
  timestamp later than `asserted_at`, ends the Label's application at
  the first Epoch whose `sealed_at` reaches it; the Label stays the
  current one, so an earlier Label does not return. Tuples and the
  label table drop an expired Label and carry `expires_at` while it
  lives.
- **A Label can bind to one publication.** An OPTIONAL `delta`, an Item
  ID, on a URL subject binds the Label to that Item: the Label applies
  only while the URL's materialized record (ADR-0039) carries the Item,
  and nothing while the URL has no materialized record or one carrying
  another Item, whatever other records of the URL exist. The binding is not checked against any Log at
  pull, since the Item may be sealed elsewhere.
- **A Labeler defines the names it uses.** A signed label definition
  per name, served under the Labeler's well-known prefix at a path
  derived from the name, carries a description URL and a default
  treatment — `hide`, `warn` or `inform` — that a Consumer applies when
  its own profile names none; no definition means `inform`. Definitions
  are not sealed: they describe how the Labeler means a name, which the
  Labeler may revise, and the Consumer keeps the newest that verifies.
- **The labeled domain can dispute.** A signed dispute names the Label
  ID and the Log position at which the disputant saw it, with an
  optional reason URL. It is published beside the Labels, listed in the
  Label Feed, sealed as its own `dispute` Entry, carried as a tuple and
  materialized in a dispute table beside the label table. The
  self-labeling rule does not apply; its inverse does: the disputed
  Label's subject must lie under the disputant's authority, and the
  Label must be sealed in the Log the Aggregator seals. Nothing in the
  suite rules on a dispute — the Aggregator applies it to nothing and
  the Consumer's profile decides what a disputed Label is worth.
- **A Labeler is bounded per Epoch.** `labeler_epoch_entries_max`
  (default 1 000) caps the `label` and `dispute` Entries of one
  Registrable Domain per Epoch, inside the per-domain capacity and
  never above it, and a Consumer rejects an Epoch over it as it rejects
  one over the capacity.
- **A sealed Label or dispute that fails its checks is ignored.** A
  `label` or `dispute` Entry failing any check WIST-2 §3.3 gives it,
  judged at its Epoch, a binding failure included, applies nothing and
  enters no table; its Epoch stays accepted and the Consumer reports the
  code. It still counts toward the capacity and the per-Labeler cap of
  the Registrable Domain its `labeler` or `disputant` names, and a
  `label` Entry whose Label ID is computable still holds that ID under
  the rule that seals a Label once.
- **A default profile is recommended.** Count `wist:mismatch` and
  `wist:unavailable` only once they persist across two consecutive
  Epochs, and ignore a Labeler with no sealed Entry within a configured
  number of Epochs, 720 by default. Both read the Log alone.
- **The Aggregator publishes labeler statistics.** A per-Labeler table
  of valid sealed Labels, retractions, distinct subjects and first-seen
  height, derived from Entry counts without reading any Label's
  meaning, so a subscription decision can start from behavior.

## Alternatives considered

- **An appeal ruled on by the Aggregator or the Labeler.** Puts a party
  in the suite in the position of judging a Label, which ADR-0041
  removed on purpose; a ruling nobody can verify is a sanction under
  another name.
- **Retraction as the only answer.** Leaves the labeled party dependent
  on the Labeler's attention; a dispute lets the answer travel with the
  claim whatever the Labeler does.
- **Definitions sealed in the Log.** Replayable, but a treatment is the
  Labeler's advice to Consumers rather than a fact about a subject, and
  sealing every revision of every name's description would spend Epochs
  on prose.
- **A single Labeler-wide cap counted per Canonical Host.** Free
  subdomains would multiply it (ADR-0042); the cap is counted per
  Registrable Domain like the capacity it sits inside.
- **A dispute count in the labeler table.** Derivable from the dispute
  table by a join; left out to keep the statistics table a pure count
  over `label` Entries.
- **Rejecting the Epoch of a failing sealed Label or dispute.** A
  Catalog or Item that fails its judgment is ignored, not fatal, and an
  opinion about another party carries no more weight in the Log than a
  publication; rejecting would let one Labeler's defect stop every
  Consumer's replay.
- **Exempting an ignored Entry from the counts.** The capacity, the
  cap and the single sealing of a Label ID are read before or beside
  judgment; counting only valid Entries would make each depend on the
  Declaration in force and the clock, and the Aggregator holds every
  Label ID it sealed as seen whatever its judgment found.
- **Binding `delta` to any record of the URL.** A URL can carry records
  under two Publishers (ADR-0039); a Label bound to an Item that a
  query never shows would apply to a record nobody reads, so the
  binding reads the one record materialized.

## Consequences

- Label objects carry nine members; label tuples carry `expires_at`,
  `delta` and the Label ID a dispute names, and the label table
  `expires_at` and `delta`; Epochs carry the `dispute` Entry type; the
  Registry carries `labeler_epoch_entries_max` with a combination rule.
- `vectors/wist2/labels.json` gains expiry, binding and Snapshot-instant
  cases; `vectors/wist2/disputes.json`, `vectors/wist2/label-definitions.json`
  and `vectors/wist3/label-tables.json` are new; the parameter
  combination vectors carry the cap rule.
- Replay judges every `label` and `dispute` Entry at its Epoch, and the
  labeler table counts valid `label` Entries alone.
- Implementations add expiry and binding to Label validation and
  materialization, dispute pulling and sealing, definition publication
  and reading, the per-Labeler cap, the two tier-1 tables and the
  default profile.
