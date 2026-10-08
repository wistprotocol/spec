# WIST-2: Site Publication

**Status:** v1.0.0-draft · **Date:** 2026-10-02 · **License:** CC-BY 4.0

## 1. Introduction

WIST-2 defines **ping + pull** publication: a Publisher serves, under its
`.well-known` path, its Declaration, the signed Catalog of each Collection
with the tree files, change lists and Payloads the Catalog names (WIST-1),
and its Labels (§3.3), and notifies Aggregators to fetch them.
These Publisher-hosted artifacts permit independent retrieval and verification
without coupling publication to one Aggregator. Design rationale:
[ADR-0003](../decisions/0003-ping-plus-pull.md).

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Ping**: the unauthenticated notification a Publisher sends an
  Aggregator's Ingest Endpoint to trigger a pull.
- **Pull**: the fetches by which an Aggregator reads one Publisher: its
  Declaration, the Catalog of each Collection with its list and the
  Payloads it needs, and its Label Feed (§5).
- **Change list**: an unsigned file stating how the list of one Catalog
  differs from the list of the Catalog it replaced (§3.1).
- **Change Hint**: an unsigned, out-of-protocol signal (IndexNow ping,
  sitemap, llms.txt) that a page may have changed.
- **Ingest Endpoint**: `POST https://<log_id>/ingest` at the
  Aggregator's Service Origin (WIST-3 §6); a Publisher learns a Log's
  `log_id` from its Log Anchor, obtained out of band (WIST-3 §3.4).
- **Label**: a Publisher's signed statement about a subject outside its
  own authority, under a name from WIST-4 §6's Label Registry (§3.3).
- **Labeler**: a Publisher in its capacity as the signer of Labels.
- **Label Feed**: the signed list of a Labeler's recent Label and Dispute
  IDs (§3.2).
- **Page**: an immutable, sealed slice of exactly 1000 older IDs evicted
  from a Label Feed, reachable by walking `next` (§3.2).

Terms defined in WIST-1 (Publisher, Aggregator, Item, Item ID,
Collection, Scope, Catalog, Catalog ID, key, leaf, root, tree file,
Envelope, Key Set, Canonical Host, Normalized URL, Payload, Payload
Commitment, Publisher Declaration), the list of a Catalog (WIST-1 §3.5)
and an idempotent re-serve (WIST-1 §7) are used with their WIST-1
meanings. The latest Catalog, the floor, a base and the records of a Log
are WIST-3 §7's; the last accepted Catalog, waiting, places, eligibility
and the inclusion ceiling are WIST-3 §3.3's. Every
Envelope in this document carries `wist_version` (WIST-1 §3.1) and the WIST-1
§4 signature block (`key_id`, `alg`, `value`).

## 3. Well-Known Layout

A conforming Publisher serves, over HTTPS only:

```
/.well-known/wist/publisher.json                         (identity — WIST-1 §5.1)
/.well-known/wist/collections/<name>/catalog.json        (the Collection's Catalog — §3.1)
/.well-known/wist/collections/<name>/tree/<hex>          (tree files — §3.1, WIST-1 §4.2)
/.well-known/wist/collections/<name>/changes/<hex>.json  (change lists — §3.1)
/.well-known/wist/collections/<name>/payloads/<hex>.json (Payloads — §3.1)
/.well-known/wist/labels/<id>.json                       (one file per Label or dispute — §3.3)
/.well-known/wist/labels/definitions/<hex>.json          (label definitions — §3.3)
/.well-known/wist/label-feed.json                        (the Label Feed — §3.2)
/.well-known/wist/label-feed/<n>.json                    (sealed Pages — §3.2)
```

`<name>` is the name of a Collection of the Declaration the Publisher
serves (WIST-1 §5.1); the implicit `default` Collection is served under the
name `default`. The Label paths exist only for a Publisher that labels or
disputes; a Publisher serving none of them is a Publisher with no Labels.
Publishers SHOULD serve `publisher.json` with `Cache-Control: no-cache`
and an `ETag`, as §3.1 asks of a Catalog: a stale Declaration served to a
validator at first contact installs a superseded identity there (WIST-1
§5.2, **First contact**).

### 3.1. Collection Files

**Catalog.** `catalog.json` contains exactly one Catalog Envelope (WIST-1
§3.5) whose `publisher` is the Publisher's `domain` and whose `collection`
is `<name>`: the Collection's **served Catalog**. Publishers SHOULD serve it
with `Cache-Control: no-cache` and an `ETag`, and Aggregators SHOULD use
conditional requests (§5.1 reads an answer 304). How a Publisher derives a
Catalog's list, chooses its `generated_at` and decides that a Catalog is
due is WIST-5's.

**Tree files.** `tree/<hex>` contains one tree file (WIST-1 §4.2), where
`<hex>` is the 64 lowercase hexadecimal digits of the SHA-256 of its
octets. Its name fixes its octets. Publishers SHOULD serve tree files,
change lists and Payloads with long-lived cache headers (`Cache-Control:
public, max-age=31536000, immutable`).

**Payloads.** `payloads/<hex>.json` contains the Payload (schema:
[`schemas/payload.schema.json`](../schemas/payload.schema.json)) of the Item
of kind `page` whose Item ID is `sha256:` followed by `<hex>` (WIST-1 §3.6).
A Payload is unsigned; its integrity comes from the Item's commitment
(WIST-1 §3.6), which every fetcher recomputes. A Payload file is immutable
while served, and erasable (below).

**Change lists.** `changes/<hex>.json` contains the change list that
**leads to** the Catalog whose Catalog ID is `sha256:` followed by `<hex>`:
the JCS serialization of one object with exactly these members.

| Member | Form |
|---|---|
| `previous` | The Catalog ID of the **previous Catalog**: the Catalog that the one the list leads to replaced |
| `catalog` | The Catalog ID of the Catalog the list leads to |
| `dropped` | An array of keys (WIST-1 §4.1), each a string of 64 lowercase hexadecimal digits, in strictly ascending octet order |
| `items` | An array of Items in strictly ascending octet order of key; each element is an object with a string member `url` |

A Catalog ID here is `sha256:` followed by 64 lowercase hexadecimal digits.
No key of `dropped` is the key of an element of `items`. The form asks
nothing else of an element: the Item conditions judge it with the list
obtained (§5.1).

A change list is **applied** to an Item list: every Item under a key of
`dropped` leaves the list, whatever its kind, and every element of `items`
takes the place of the Item under its key or, where the list holds none
under it, enters the list. A key of `dropped` under which the list holds no
Item, and an element equal to the Item it replaces, change nothing and fail
nothing.

The part of a Publisher that signs (WIST-5), when it signs a Catalog of a
Collection with a served Catalog, writes the change list that leads to the
new Catalog, with the served Catalog as its previous Catalog: `items` holds
every Item of the new list under whose key the served list holds no Item or
an Item of another Item ID, and `dropped` the key of every Item of the
served list under whose key the new list holds none, an Item of kind
`removed` that leaves after `removal_retention_days` (WIST-1 §3.3)
included. A Catalog whose list is the served one has both arrays empty.
Where the file would hold more than `change_list_cap_bytes` octets, none is
written. A Catalog signed for a Collection with no served Catalog has no
change list. A Catalog whose Catalog ID is the served Catalog's is the
served Catalog, not a new one: no change list is written for it, and the
change list that leads to the served Catalog stays as it is.

The **chain** of a Catalog is its change list, then the change list that
leads to that list's previous Catalog, and so on. It ends at a Catalog for
which no change list was written or whose change list the Publisher had to
stop serving.

`change_list_cap_bytes` is 1 048 576 octets, `change_chain_max` 16 change
lists and `replaced_file_seconds` 86 400 seconds. They are values of the
suite: no Log amends them and no parameter map carries them, since a
Publisher reads no Log's parameters and no Consumer derives a value from
the files they bound.

**Payload retention.** A Catalog **names** the tree files reached from its
`tree` and the Payloads of the Items of kind `page` of its list. A
Publisher MUST write every file a Catalog names, and the Catalog's change
list, before it serves that Catalog, and MUST serve every file the served
Catalog names and the first `change_chain_max` change lists of its chain,
so the Payload of every Item of kind `page` it lists stays retrievable. It
MUST also serve:

- a file the served Catalog does not name, at every instant earlier than
  the instant at which the last Catalog that named it was replaced plus
  `replaced_file_seconds`, counted on the Publisher's clock; a file named
  again inside that interval is served as a named one;
- a change list that a new Catalog puts out of the first
  `change_chain_max` of the chain, at every instant earlier than the instant
  at which that Catalog began to be served plus `replaced_file_seconds`,
  whatever Catalogs follow; a list that leaves the chain because the chain
  ends in front of it has no interval;
- the files and change lists it was obliged to serve for a Collection that
  the served Declaration stops naming, at every instant earlier than the
  instant at which it began to serve that Declaration plus
  `replaced_file_seconds`.

Outside these duties the Publisher may stop serving a file, and no rule
obliges it to. A file the Publisher must stop serving — a withdrawn Payload
(below), or a file it must remove for a reason outside this suite — is
removed at once, whatever Catalog names it, wherever it stands in a chain
and whatever interval it is inside. The Aggregator's own retention of
Payloads is WIST-3 §6.1's.

**Withdrawal ends that duty and every other reason to serve.** From the
height a `payload_withdrawal` naming an Item ID is sealed (WIST-3 §6.2),
the Publisher MUST stop serving that Item's Payload at
`payloads/<hex>.json`, and the retention duty above does not survive it — the two do not compete. A
Publisher that keeps emitting the withdrawn content holds no Payload for
that Item, and so lists a new Item under a fresh salt (WIST-1 §3.6).
Withdrawal reaching the Aggregator and the Mirrors but not the site that
first published the content would leave the salt on the open web at a
well-known path, and with it the commitment the salt keys (WIST-1 §3.6).
One serving
path left open is the whole of the guarantee gone, which is why WIST-3 §6.2
binds all three.

### 3.2. The Label Feed and its Pages

`label-feed.json` is an Envelope whose inner object is `feed` (schema:
[`schemas/feed.schema.json`](../schemas/feed.schema.json)): `domain`,
`generated_at`, `deltas` — the Label and Dispute IDs (§3.3) of the Labeler,
in publication order, newest last; the member lists no other kind of ID —
and `next`. `generated_at` MUST be monotonically non-decreasing across
successive versions of `label-feed.json`; an Aggregator MUST discard a
Label Feed whose `generated_at` has regressed, with every Page and ID its
walk would read, under `WIST2-E05`.

A Label Feed or Page is usable only once it passes, in this order, the
Feed schema, its formats and WIST-1 §4 canonicalizability included, with
`wist_version` spelled as WIST-1 §3.1 spells a Catalog's and
`generated_at` in WIST-3 §3.1's whole-second profile; a `domain` equal to
the requested host, since one naming another domain does not authenticate
as this domain's whatever its signature verifies against; and its
signature, verified against the domain's Key Set (WIST-1 §5) for the live
`label-feed.json` and under the sources below for a Page. Signed fields are
never normalized.

For each requested Canonical Host, the Aggregator MUST durably retain the
greatest `generated_at` of a live `label-feed.json` that passed those
checks. After those checks and before following `next` or admitting Labels,
it MUST atomically compare and retain that timestamp. A smaller value is
`WIST2-E05`; equality passes. Failed field, domain or signature checks take
precedence and MUST NOT change the retained value. Failure to persist the
comparison result MUST stop the Label walk before Page or Label work.

Later Page, Label or dispute failures, budget suspension and an empty or
already-ingested Label Feed MUST NOT undo this observation. Sealed Pages
neither compare against nor advance this live value. The value survives
restart and all Declaration changes, including recovery settlement and
identity reset; it is scoped to the requested host, not a signing key or
identity interval. A host without a retained observation starts with its
first authenticated live Label Feed. The validator clock imposes no
additional bound on `generated_at`. See
[ADR-0033](../decisions/0033-feed-regression-state.md).

**Publication order** is the order in which the Labeler first added each ID
to the Label Feed.

**Page sealing.** When appending an ID would make `deltas` exceed 1000
entries, the Labeler MUST first seal the current 1000 entries into an
immutable Page at `/.well-known/wist/label-feed/<n>.json`. `<n>` is a
zero-based counter assigned in sealing order — `0` for the first Page a
domain ever seals (its oldest content), incrementing by exactly one each
time a further Page is sealed, and never reused or reassigned once
published, so a Page's URL and bytes never change. The Labeler MUST
publish the new Page's file at its URL *before* removing the newly-sealed
entries from the live `label-feed.json` and updating its `next` — so at
every instant, each ID being sealed is retrievable either from the live
`label-feed.json` (not yet cut over) or from the new Page (already
published), never from neither. Once cutover completes,
`label-feed.json`'s `next` names the highest-numbered (most recently
sealed) Page's absolute URL. Each Page carries the same schema and the same
`domain`, and its own `next` names the next-*older* Page — Page `<n-1>`'s
absolute URL, or `null` for Page 0, which has no older Page before it.
Pages MUST partition the Labeler's history: every ID the Labeler has ever
sealed into a Page MUST appear on exactly one Page, never on two and never
on none.

**Verification of sealed pages.** Verify a Page under WIST-1 §4 using the
signing entry whose `kid` equals its `sig.key_id` in the Declaration
current at `generated_at`. If no usable named entry verifies, try the
Declaration selected from the first following Epoch by the bridge below.
An absent current Declaration also permits this fallback. Each attempt
MUST use that Declaration's own named entry. Finding `sig.key_id` in
current does not suppress fallback when its entry fails verification. No
other Declaration supplies authority, a pending Declaration (WIST-1 §5.2)
supplies none, and the `nbf`/`exp` window of WIST-1 §5.1's binding check
does not apply to Pages. A Page that verifies under neither source is
`WIST2-E04`.

Pages are immutable and never re-signed on rotation. A validator MUST NOT
reject a Page solely because its signing key has since been retired or its
authorizing Declaration had not sealed when the Page was cut.

A Page's `generated_at` is the instant of the cutover that sealed it — the
same value the `label-feed.json` published at that cutover carries — and
not the instant the entries on it were first added to the Label Feed. The
Page is signed at cutover, by whichever key the Labeler holds then, and the
rule above resolves its Key Set through this field; stamping it with an
earlier instant would resolve a Key Set that need not contain the key that
signed the Page, so a Page honestly sealed after a rotation would fail
verification under its own signature. Sealing order and page numbering
therefore agree with `generated_at` order, which is the same
non-decreasing sequence this section already requires of successive
`label-feed.json` versions.

WIST-1 §5.2's historical-verification procedure cannot be applied directly
here: it resolves a Key Set by **Epoch number**, and Pages are never sealed
into the Log, so a Page has no height. The bridge is stated once, and it is
the only conversion permitted: the Key Set current at a `generated_at` is
the one declared by the domain's `publisher_declaration` Entry (WIST-3 §3.3)
with the greatest `sealed_at` not later than that `generated_at` — the
highest `seq` among them where one Epoch seals several, which is the Key
Set WIST-1 §5.2 resolves at that Epoch's height — with
WIST-1 §5.2's recovery exception applied to that comparison exactly as it is
applied to the by-height one, so a Declaration superseded by a recovery
rotation is excluded here too. `sealed_at` is strictly increasing across
Epochs (WIST-3 §3.1), so the ordering by `sealed_at` and the ordering by
height are the same ordering; what changes is only the key the Consumer
looks the Declaration up by, because a Page carries a timestamp and not a
height. Every input is in the Log, so two validators resolve the same Page
to the same Key Set. Because that comparison is against an Epoch's
`sealed_at`, `generated_at` carries the same whole-second, literal-`Z` form
`sealed_at` does (`schemas/feed.schema.json`, WIST-3 §3.1): the two values
compare directly, with no normalization step for two implementations to
perform differently.

A Page can be cut under a key no sealed Declaration yet holds. The
Labeler rotates and seals a Page in one act, and the Declaration
recording the rotation seals only when an Aggregator next pulls it — or,
before first contact, when an Aggregator first learns the domain exists,
which can be a thousand Labels and several Pages after the Labeler
started. A Catalog has no such gap, because an Aggregator seals the
Declaration a pull read at or below the Epoch that seals the first
publication that pull accepted (WIST-1 §5.2) and seals a Catalog only where
it verifies at its Epoch (WIST-3 §3.3); a Page is never sealed, so nothing
holds it. The second
resolution above closes the gap: fallback selects the Key Set of the
**first** Epoch sealed after `generated_at` that seals an
applicable Declaration of the domain — the same recovery exception
applied — the Labeler's own act attested one seal late. Where that
Epoch seals several Declarations of the domain, the Key Set is the
highest `seq`'s, exactly as at a height: the lower one was the Key Set
at no instant — WIST-1 §5.2 resolves the higher `seq` at that Epoch —
and a Page accepted under it would be one no Catalog could ever have been
sealed under. It is the first such Epoch and not any later one, so a
Page cannot claim a key from a rotation two seals ahead; and both
lookups read Epochs every validator holds, so two validators still
resolve one Page to one answer. A Page cut before the domain's first
Declaration sealed resolves, by the same rule, to that Declaration's
Key Set.

**Aggregator obligation.** On each pull, an Aggregator MUST follow `next`
until it reaches a page whose newest ID it has already seen (§5.5), or
until `next` is `null`, applying the same fetch-validate-queue procedure
(§5.5) to every page's IDs as to the live `label-feed.json`'s. Diffing only
the live `label-feed.json` is non-conforming and loses Labels whenever more
than one window's worth is published between pulls.

**Target rule.** An Aggregator reads `next` only when the walk continues
past the object carrying it: after that Label Feed or Page passed the
checks above — and, for the live `label-feed.json`, the `generated_at`
comparison — and only if it lists an ID not yet seen.
An unread `next` is checked against nothing. A `next` the Feed schema
rejects — not a string, not `https`, carrying a fragment — fails the schema
check of its whole Label Feed or Page and never reaches this rule. A
read `next` MUST be byte-identical to its own Normalized URL (WIST-1 §2)
and MUST begin with `https://`, the requested Canonical Host and
`/.well-known/wist/`, in those octets: no userinfo, no port, no
`subdomain_scope` host, and a query fetched as written. No Declaration
supplies this rule's inputs, so a rotation or recovery settlement cannot
change a target's disposition; §8 still governs redirects from an accepted
target. A `next` failing the rule is `WIST2-E01`: the walk stops there with
no usable Page, exactly as it stops at a Page it cannot fetch, an
Aggregator MUST NOT fetch it, and the IDs of the Label Feed and Pages
already fetched proceed under §5.5. Byte-identity decides encoded
spellings: `%2E%2E`, `%7e` and `:443` normalize away, so no URL spelling
them is identical to its normalization, while `%2F` stays encoded and a
path beginning `/.well-known/wist%2F` does not begin with the prefix.

**Caching.** Publishers SHOULD serve `label-feed.json` with `Cache-Control:
no-cache` and an `ETag`; Aggregators SHOULD use conditional requests, and an
answer 304 lists no new ID. Sealed Pages are immutable and SHOULD instead be
served with long-lived cache headers, as in §3.1.

### 3.3. Labels

A Publisher MAY publish **Labels**: signed statements about subjects
outside its own authority, each under a name from the Label Registry
(WIST-4 §6). A Label is an Envelope whose inner object is `label`
(schema: [`schemas/label.schema.json`](../schemas/label.schema.json)),
carrying:

- `wist_version` (WIST-1 §3.1);
- `labeler` — the Labeler's Canonical Host, in the form and with the
  binding a Catalog's `publisher` carries (WIST-1 §3.8): the Label's
  identity and its signature authority;
- `subject` — a Normalized URL (WIST-1 §2), byte-identical to its own
  normalization, or a Canonical Host; in JCS octets it MUST NOT exceed
  `url_cap_bytes` (WIST-4 §5);
- `name` — a Label Registry name (WIST-4 §6);
- `value` — OPTIONAL, an integer in micro-units, 0 … 1 000 000;
- `asserted_at` — the instant the Labeler asserts the statement for, a
  Publisher timestamp under WIST-1 §3.4's profile, bound above by the clock
  rule WIST-1 §3.4 gives a Catalog's `generated_at`, with the clock and
  parameter time that section selects for a Catalog at the same stage;
- `retracted` — OPTIONAL, `true` where the Label withdraws the Labeler's
  earlier Label of the same `name` on the same `subject`;
- `expires_at` — OPTIONAL, the instant from which the Label applies
  nothing, a Publisher timestamp under the same profile as
  `asserted_at`; it MUST be later than `asserted_at`, and one that is
  not is `WIST2-E06`;
- `delta` — OPTIONAL, only with a Normalized URL `subject`, an Item ID
  that binds the Label to one publication: the Label applies only while
  the subject URL's materialized record (WIST-3 §7, **One URL, one
  Publisher**) carries that Item, and applies nothing while the URL has
  no materialized record or its materialized record carries another
  Item, whatever other records of the URL exist. A `delta` beside a
  Canonical Host `subject`, or
  one that is not an Item ID in form, is `WIST2-E06`; whether the Item is
  sealed in any Log is not checked, since a Labeler may bind to a
  publication another Log sealed.

Those nine members and no others. The **Label ID** is `"sha256:" +
hex(SHA-256(JCS(label)))`, the construction WIST-1 §4 uses for a Catalog
ID. A Label is signed under the Labeler's Key Set by the binding check
WIST-1 §5.1 gives a Catalog, with `asserted_at` in the place of
`generated_at` for key validity, over `keys` alone, since a Collection's
keys sign its Catalogs and nothing else (WIST-1 §5.1), and WIST-1 §4's
profile; `labeler` MUST equal the Declaration's `domain` (WIST-1 §3.8).

**Self-labeling is rejected.** A Label whose `subject` is a Normalized
URL under the Labeler's own authority — its `domain` or a host its
`subdomain_scope` names (WIST-1 §3.2) — or a Canonical Host equal to that
domain or to a scoped host, is a statement about the Labeler itself,
which WIST-4 §4 forbids: it is rejected under `WIST2-E06` and never
sealed. Everything else is outside the scope rule by design: a Label is
an opinion about another party, and the Log records who signed it.

**Files.** `labels/<id>.json` contains exactly one Label Envelope,
immutable once published, its filename the 64 hexadecimal digits of the
Label ID that follow `sha256:`, served with the cache headers §3.1 advises
for a tree file. A Labeler lists each Label it publishes in its Label Feed
(§3.2), a sequence of its own beside its Catalogs; the two share a
Declaration and a Key Set.

**Which Label is current.** For each (labeler, subject, name), the
Labeler's current Label at a height is the sealed Label with the
greatest `asserted_at`, and among equal instants the one later in Log
order (WIST-3 §3.3: ascending Epoch number, then Entry index). A current
Label with `retracted` `true` means the Labeler asserts nothing about
that subject under that name; every earlier Label stays sealed. A Label
whose `asserted_at` is earlier than the current Label's is sealed and
applies nothing. A current Label with an `expires_at` applies nothing
at an Epoch whose `sealed_at` is at or after that instant — compared as
instants, the Publisher timestamp converted exactly — and it stays the
current Label, so an earlier unexpired Label does not return; a Labeler
that wants the subject labeled again asserts anew. Consumers read
Labels through their Snapshot tuples and `tier1/labels.parquet` (WIST-3
§7), which carry the current, unretracted, unexpired Labels with their
`expires_at` and `delta`, and apply only the Labelers they subscribe to
(WIST-4 §6).

**Label definitions.** A Labeler SHOULD publish, for every `name` it
uses, a **label definition**: an Envelope whose inner object is
`definition` (schema:
[`schemas/label-definition.schema.json`](../schemas/label-definition.schema.json)),
carrying `wist_version`, `labeler` (bound as a Label's is), the `name`,
a `description` — a Normalized URL where the Labeler describes what the
name means and how it applies it — a `treatment`, one of `hide`, `warn`
and `inform`, the treatment a Consumer applies to the name's subjects
when its own profile names none (WIST-4 §6), and `asserted_at`, read
as a Label's. It is served at `labels/definitions/<hex>.json`, where
`<hex>` is the lowercase hex SHA-256 of the name's UTF-8 octets, and is
signed under the Labeler's Key Set as a Label is. A definition is not
sealed and not pulled by an Aggregator: a Consumer fetches it for each
name of a Labeler it subscribes to, keeps the newest `asserted_at` that
verifies, and treats a name with no verifiable definition as `inform`.
A definition for a `wist` term describes the Labeler's own application
of the registry's meaning, which it cannot change.

**Disputes.** The domain a Label is about MAY publish a **dispute**: an
Envelope whose inner object is `dispute` (schema:
[`schemas/dispute.schema.json`](../schemas/dispute.schema.json)),
carrying `wist_version`, `disputant` — the disputing Publisher's
Canonical Host, bound as a Label's `labeler` is — `label`, the disputed
Label's ID, `log` and `height`, the `log_id` and Epoch number at which
the disputant saw the Label sealed, an OPTIONAL `reason`, a Normalized
URL where the disputant states its grounds, and `asserted_at`, read as
a Label's. Those seven members and no others; the **Dispute ID** is the
Label ID construction over `dispute`. A dispute is published at
`labels/<id>.json` beside the Labels — the directory holds Label and
Dispute Envelopes alike, told apart by their inner member — and listed
in the Label Feed like a Label. It is signed under the disputant's Key
Set by the rule a Label is signed under. The self-labeling rule does not
apply: a dispute references a Label rather than asserting anything
about its signer, and the opposite constraint holds instead — the
disputed Label's `subject` MUST lie under the disputant's authority
(its `domain` or a scoped host, or a URL under either, WIST-1 §3.2), and
the Label MUST already be sealed in the Log the Aggregator seals; a
dispute failing either, or a field check, is rejected with `WIST2-E06`
at that pull and not sealed, and one whose Label is unsealed is judged
again at the next pull (§5.5). `log` and `height` are the disputant's citation: an Aggregator
MUST NOT reject a dispute for naming another Log or a height at which
its own Log did not seal the Label. For each (label, disputant) the
current dispute is chosen as a Label is, by `asserted_at` and then Log
order. A dispute is never applied by the Aggregator or a Snapshot
builder: it alters no Label, tuple or record. It is sealed as a
`dispute` Entry (WIST-3 §3.3), carried as a `dispute` tuple and
materialized in `tier1/disputes.parquet` beside the labels (WIST-3 §7),
so that a Consumer weighing a Labeler sees what the labeled parties
answered, without any party in the suite deciding who is right.

**Pull.** An Aggregator pulls a Labeler's Labels and disputes under §5.5.

## 4. The Ping

To notify an Aggregator, a Publisher sends:

```
POST https://<log_id>/ingest
Content-Type: application/json

{"host": "example.com"}
```

`host` MUST be a Canonical Host (WIST-1 §2). An Aggregator MUST reject a
ping whose `host` is not canonical, and MUST reject a Catalog that names
another Publisher or Collection than the one it was fetched for, with
`WIST2-E04` (§7, WIST-1 §7): such a Catalog does not authenticate as this
Collection's Catalog, whatever its signature verifies against.
WIST-1 §7's field precedence applies before this comparison.

The Ping carries no content and no signature; authenticity comes from the
subsequent HTTPS pull of the signed Declaration, Catalogs and Label Feed.
Responses:

| Status | Meaning |
|--------|---------------------------------------------------|
| 202 | Accepted; a pull will follow |
| 429 | Rate-limited; MUST include `Retry-After` |
| 403 | The Aggregator does not ingest this domain, for a reason outside this suite — an operator's legal obligation is the case foreseen. The refusal MUST be visible as the `refused` state at the status endpoint (§7.1), and WIST-4 §4's invariants still bind: a refusal is not for sale and never a treatment of one Publisher's content against another's. |

On a 5xx, timeout, or connection failure a Publisher SHOULD retry at most
three times with exponential backoff (1 min, 4 min, 16 min) and then rely
on the Aggregator's baseline polling; it MUST NOT retry a 4xx other than
429.

The Ping quota Q is `quota_base` Pings per UTC day per Registrable
Domain (WIST-4 §5), the same for every Registrable Domain: a Ping for a
Canonical Host counts against the Registrable Domain of that host under
the Public Suffix List snapshot in force at the Ping (WIST-4 §3.1), so
hosts under one registrable name share one quota while hosts under a
private-section suffix hold their own. Counts are kept per Registrable
Domain as named under the snapshot in force at each Ping: when an
accepted `suffix_list_update` changes a host's Registrable Domain
inside a day, the Pings already counted stay under the unit they were
counted against, and from its next Ping the host counts against the
unit it now belongs to, starting from whatever that unit already
carries. Only pings resolving to
`WIST2-E02` or `WIST2-E04` count against it; productive pings do not.
Once Q is reached, every Ping for a host of that Registrable Domain
yields `429` until the UTC-day window resets.

## 5. Aggregator Pull Behavior

An Aggregator pulls a Publisher on an accepted Ping (§4) and at the
baseline interval (§5.4). The files of Collection `<name>` that a pull
fetches are those §3 lays out under
`https://<domain>/.well-known/wist/collections/<name>/`, where `<domain>`
is the requested Canonical Host: `catalog.json`, `tree/<hex>`,
`changes/<hex>.json` and `payloads/<hex>.json`.

### 5.1. The Pull Sequence

0. **Declaration and first contact.** At the start of every pull the
   Aggregator fetches `publisher.json` and applies it under WIST-1 §5.1
   and §5.2; no Declaration is read from a cache in its place. An answer
   304 to a conditional request is judged as an answer 200 carrying the
   Declaration whose validator the request sent: a success of the fetch
   where WIST-1 §5.1 (**Size**) reads that Declaration as served again,
   and a failed fetch where WIST-1 §5.2 rejects it, as it rejects a
   competitor superseded at settlement. The pull proceeds only after that fetch
   succeeds. Where the fetch fails, or the fetched Declaration fails its
   acceptance checks — a recovery rotation whose window would end after
   `9999-12-31T23:59:59Z` included (WIST-1 §5.2) — the Aggregator pulls
   no Collection and no Label Feed of the Publisher in that pull. The
   recovery-chain head of an open window served again is no such failure:
   although its acceptance answers `WIST1-E08`, it is a success of the
   fetch, and the pull proceeds (WIST-1 §5.2, **Sources of a pull**).

   A domain is in **first contact** while no accepted Declaration of it
   remains (WIST-1 §5.2): first contact ends at the pull that accepts the
   domain's first Declaration, sealed or not. That Declaration is accepted
   at any `seq` (WIST-1 §5.2, **First contact**): an Aggregator that first
   meets a Publisher after its rotations admits the Declaration it serves
   then. A first-contact pull whose
   `publisher.json` is missing, unreachable, malformed, or fails WIST-1
   §5.1 or §5.2 is `WIST2-E04`. Outside first contact, a pull stopped at
   its Declaration is one failed fetch, `WIST2-E01`: retried on §7's
   backoff and not noise (§4). An accepted Declaration is sealed as a
   `publisher_declaration` Entry (WIST-3 §3.3) under WIST-1 §5.2.
1. **Collections.** The pull reads each Collection the sources of the
   pull name, in the order WIST-1 §5.2 (**Sources of a pull**) gives,
   through steps 2 to 4. One Collection's failure stops no other
   Collection.
2. **Catalog.** The Aggregator fetches the Collection's `catalog.json`.
   A fetch that fails, an answer above §8's bound included, is
   `WIST2-E01`. An answer 304 to a conditional request is judged as an
   answer 200 carrying the Catalog whose validator the request sent. The
   fetched Catalog is judged by WIST-1 §7's Catalog conditions against
   the Publisher and the Collection it was fetched for, under the sources
   of the pull (WIST-1 §5.2), with the clock and the parameter map WIST-1
   §3.4 and §3.6 select for its validation attempt; each pull begins a new
   validation attempt for the Catalog it fetches. A Catalog that meets a
   condition is reported (§7.1) with its code, replaces nothing and
   retries nothing. One that meets none is read for the order and for an
   idempotent re-serve (WIST-1 §7), which inside a recovery window, and
   from the discovery of a recovery rotation, read the queue as WIST-1
   §5.2 (*Queue*) gives. An idempotent re-serve replaces no Catalog,
   fetches no tree file the Aggregator holds and gives no waiting Item
   another place (WIST-3 §3.3); the pull goes on to step 4 for the Items
   of its list that are not admitted.
3. **List.** For a Catalog that passed step 2 and is no idempotent
   re-serve, the Aggregator obtains its list (§5.3). A Catalog whose walk
   meets a condition of §5.3 is refused whole with `WIST2-E07`, and
   nothing of it is sealed. It is refused whole with `WIST2-E07` as well
   when its list holds no Item for the URL of a record that the
   Aggregator's Log holds for the Publisher in that Collection (WIST-3
   §7) and that the Collection's Scope covers under the Declaration the
   pull reads, under two frozen sources the Scope of either (WIST-1
   §5.2), unless the Catalog is a base against the floor (WIST-3 §7): no
   Entry could remove that record. An Item the list holds for the URL
   counts whether or not it is refused alone. The report of this refusal
   (§7.1) names the URL of every such record. A refused Catalog is
   fetched again at the next pull. A Catalog that passes is **accepted**:
   it becomes the Collection's last accepted Catalog and waits for sealing
   (WIST-3 §3.3), or, from the discovery of a recovery rotation until the
   settlement of its window, is queued (WIST-1 §5.2).
4. **Items and Payloads.** Every Item of an accepted Catalog's list, and
   every Item that is not admitted of the list of an idempotent re-serve
   — those refused or no longer admitted at their turn included — is
   judged under the sources of the pull:
   - An Item of kind `page` whose Item ID a `payload_withdrawal` sealed in
     the Log and meeting its contract (WIST-4 §5.1) names (WIST-3 §6.2)
     is not admitted, its Payload is not fetched, and it is reported with
     `WIST2-E03`, whatever Item condition other than a `WIST1-E14` one it
     meets.
   - Any other Item is judged by WIST-1 §7's Item conditions with the
     Catalog; under two frozen sources, by each source that accepts the
     Catalog (WIST-1 §5.2). An Item that meets one is refused alone and
     reported with its code; the other Items proceed.
   - An Item that meets none is **admitted** when it is of kind
     `removed`, when it is the Item of its URL's record, whose Payload the
     pull does not check, or when its Payload verifies. For any other Item
     of kind `page` the Aggregator fetches its `payloads/<hex>.json`,
     unless it holds a Payload under that Item ID, and verifies the
     Payload, held or fetched, by WIST-1 §7's Payload checks against the
     Item's `payload`, under the parameter map WIST-1 §3.6 selects at
     admission. An Item whose Payload is unavailable or fails a check is
     not admitted and is reported with `WIST2-E03`, and the other Items
     proceed: the Aggregator cannot undertake to serve (WIST-3 §6.1)
     content it never received.

   Admitted Items wait for sealing with the places, eligibility and
   inclusion ceiling WIST-3 §3.3 gives, which also checks the Payload of
   an Item of kind `page` again at its turn; from the discovery of a
   recovery rotation until the settlement of its window they are held as
   WIST-1 §5.2 gives.
5. **Labels.** The pull ends with the Label Feed (§5.5).

### 5.2. The Ingest Budget

A pull has no file cap beyond the bounds of §5.3 and WIST-1 §4.2, and a
Label walk has no page cap, so a first contact — or a long-dormant
domain's return — can demand every Collection's list with its Payloads,
up to `catalog_items_max` Items each, and a Labeler's whole history, and
a hostile domain can make both as large as those bounds allow: a single
Ping would otherwise oblige terabytes of pulls, an amplification no quota
reaches because productive pings are unmetered (§4). Here a **walk** is
the fetching a pull does after its Declaration: the Catalogs, change
lists, tree files and Payloads of its Collections, and its Label walk. The
Aggregator applies a per-domain budget, accounted per Registrable Domain
(WIST-4 §3.1) so that a free hostname is not a free budget, keyed at each
fetch as §4 keys the quota at each Ping: it MUST
fetch no more than
`ingest_budget_bytes_day` (Parameter Registry; default 1 GiB) of
Catalogs, change lists, tree files, Payloads, Label Feeds, Pages, Labels
and disputes for the hosts of one Registrable Domain per UTC day, MAY
suspend the walk when the budget is spent, and MUST resume it — from
where it stopped, which §5.3 defines for the list of a Catalog and §3.2's
"until already seen" rule for a Label walk — on a later day rather than
treat the suspension as completion. The budget bounds the walk
without breaking it: an honest large site backfills across days; a
hostile deep tree costs its own hosting bill, not the Aggregator's month.
An Aggregator MAY suspend a walk below the budget under a per-pull limit
of its own, in octets or in objects, so that one Ping cannot hold a pull
for a whole day's budget; it resumes such a walk at a later pull as it
resumes a budget suspension. As an object's octets are read, the bound
met first decides. Where what remains of the budget or of a per-pull
octet limit is smaller than the object's own response bound (§8) plus one
octet, an object that would cross that remainder is not read past it:
the octets read are debited and the walk suspends there.
Otherwise an object above its own bound is a failed fetch, not a
suspension, and debits nothing; a change list so meets `size` (§5.3).
Where a per-pull limit in objects leaves no object, the walk suspends
before the next request. A Catalog whose list a suspension interrupts is
neither accepted nor refused; one whose Items it interrupts is accepted,
and its remaining Items are judged at the later pull that meets that
Catalog again as an idempotent re-serve (§5.1 step 4); a pull whose
Catalog is refused judges none of them.

Declaration requests are outside this byte budget: the `publisher.json`
request that opens every pull MUST NOT debit it, and exhaustion MUST NOT
defer it. A Declaration request alone neither completes a walk nor makes a
refused Catalog accepted. Declaration requests remain subject to WIST-1
§5.1 and §8's transport rules. See
[ADR-0031](../decisions/0031-declaration-refresh.md).

### 5.3. The List of a Catalog

**Held lists.** An Aggregator **holds the list** of a Catalog when it
holds the Item list that it obtained for the Catalog of that Catalog ID —
by a walk, by a chain or by rule 1 below — and that list has that
Catalog's `size` and `root`, also where §5.1 step 3 then refuses the
Catalog for a list that drops a record's URL, so a later pull of the same
Catalog fetches nothing for its list. Which lists it keeps beyond those
this document and WIST-3 §3.3 read is its own matter.

**Change lists.** In place of the walk, at a pull outside or inside a
recovery window, an Aggregator MAY obtain the list of a Catalog as
follows:

1. Where a list it holds for a Catalog of the Publisher and the Collection
   has `size` Items and the root `root`, that list is the Catalog's, and
   no file is fetched.
2. Otherwise, where it holds the list of some Catalog of the Publisher and
   the Collection, it fetches the change list that leads to the Catalog
   and, while the list last read names a previous Catalog whose list it
   does not hold, the change list that leads to that Catalog. The first
   list read whose previous Catalog's list it holds ends the reading.
3. It applies the lists read to the held list of that previous Catalog,
   the list read last first and the list that leads to the fetched Catalog
   last. The result is the fetched Catalog's list when it holds `size`
   Items and its root is `root`.
4. An Aggregator that holds no list of a Catalog of the Publisher and the
   Collection reads no change list.

The pull then proceeds as after a walk (§5.1 steps 3 and 4). The tree of a
Catalog whose list was obtained so is not fetched and is judged by no
rule. An Aggregator may leave a chain at any list and walk the tree; a
chain left so is neither discarded nor reported.

An Aggregator reads at most `change_list_cap_bytes` octets of a change
list (§8). The octets of each list read are debited to the ingest budget
at each reading of a list read more than once, whether its chain is
accepted or discarded and whether or not the list meets `form`; an answer
above `change_list_cap_bytes` debits nothing. Under a per-pull limit in
objects a change list is one object; where the limit leaves no object,
the pull suspends before requesting the next change list, which does not
meet `fetch`. A change list of as many octets as the remaining budget or
a per-pull octet limit leaves is read whole; one of more octets is read
as §5.2 gives, and where the pull suspends there the list is read for no
condition below. A chain a suspension interrupts is then left: it is neither discarded nor reported, and the lists read are
not kept. An Aggregator that left a chain of a Collection so reads no
change list of that Collection until it has obtained a list of a Catalog
of it: at its next pulls it obtains the list of the Catalog then served by
rule 1 or by the walk, which resumes from the tree files held.

A chain is **discarded** at the first condition below that it meets. For
each list, in the order of reading, `fetch` is read, then `size` or the
budget, whichever §5.2 decides is met first, then `form`, then whether the
Aggregator holds the list of the previous Catalog, then `chain`; `result`
is read once the reading has ended.

| Condition | Met when |
|---|---|
| `fetch` | The fetch of a change list fails, a Publisher that serves no file at the path included |
| `size` | The answer holds more than `change_list_cap_bytes` octets; such an answer is not `fetch` |
| `form` | The octets of a change list are not the JCS serialization of an object of the form of §3.1, octets that are not valid JCS input included, or its `catalog` is not the Catalog ID that names the file |
| `chain` | `change_chain_max` lists were read and the last names a previous Catalog whose list the Aggregator does not hold |
| `result` | The lists applied give a list that holds another number of Items than `size` or has another root than `root` |

A change list that names as its previous Catalog one to which a list
already read leads is read as any other: the list that leads to that
Catalog is fetched again, so the chain meets `chain`.

A discarded chain accepts nothing and refuses nothing. The lists read are
not kept, and the Aggregator walks the tree from `tree` with the tree
files it holds; the walk alone accepts the Catalog or refuses it with
`WIST2-E07`. The walk belongs to the pull that discarded the chain: it
reads `tree_file_cap_bytes` and `tree_depth_max` from the parameter map of
that pull and counts against the budget the chain left. A discard adds no
noise (§4) and starts no retry (§7). A later pull reads the chain of the
Catalog then served, whatever chain an earlier pull discarded. A
discarded chain is reported (§7.1) with `WIST2-E08`, the name of the
condition, the Catalog ID of the fetched Catalog and the Catalog ID that
names the change list at which the condition was met, for `result` the
fetched Catalog's.

**Walk.** An Aggregator that obtains the list neither from a held list
nor from change lists walks the tree from `tree`, depth-first: it reads
the root tree file and then the children of each inner file in their
order, reading each child's whole subtree before the next child, and
fetches `tree/<hex>` for each file it does not hold under that hash. The Items of
the buckets, in the order of the walk, are the list. The walk reads
`tree_file_cap_bytes` and `tree_depth_max` (WIST-4 §5) from the parameter
map WIST-1 §3.6 selects for the Catalog's validation attempt at the pull,
a walk resumed at a later pull reading that pull's map. It stops at the
first of these conditions it meets, in the order of the walk, and fetches
no file after it:

- the fetch of a tree file fails, or a tree file holds more than
  `tree_file_cap_bytes` octets, its own response bound (§8), met first as
  §5.2 gives, or has another SHA-256 than the hash that names it;
- a tree file differs from the form of WIST-1 §4.2, its octets not being
  the JCS serialization of the object they parse to included;
- a prefix, a count, an order or a level differs from WIST-1 §4.2's rules;
- the list holds another number of Items than `size`, or its root is not
  `root`.

A condition that reads only one tree file and the entry that names it is
met when that file is read: for an inner file, its form, the prefixes of
its entries, their order, the sum of their counts against the count of
that entry (for the root tree file, `size`) and its level. No file named
by an inner file that meets such a condition is fetched.

The bounds hold the walk to the root tree file and, for each Item
counted, at most `tree_depth_max` − 1 files below it. A walk that meets a
file the Publisher no longer serves fails that fetch. A walk that the
ingest budget or a per-pull limit suspends is not refused and resumes at
the next pull, under the Catalog then served, from the files held. An
Aggregator keeps every tree file it read whole whose SHA-256 is the hash
that names it, whatever the walk's outcome, and may discard a tree file
that no last accepted, waiting or queued Catalog of the Collection names.

### 5.4. Pull Resolution and Polling

A pull at which no Declaration is discovered (WIST-1 §5.2), no Catalog is
accepted and no Item, Label or dispute is admitted resolves to `WIST2-E02`
(§4), unless it stopped at its Declaration outside first contact (§5.1
step 0) or suspended under the ingest budget or a per-pull limit (§5.2):
neither is noise. A first-contact pull stopped at its Declaration is
`WIST2-E04` and counts as noise (§4, §7). The pull that later completes
the suspended work resolves by this rule. An
idempotent re-serve discovers or accepts nothing; a Catalog that cannot be
fetched or is refused, with `WIST2-E07` or another code, accepts nothing;
and a discarded chain adds nothing of its own (§5.3).

Aggregators MUST also poll every known Publisher at a low baseline
frequency (default: every 24 hours, a Parameter Registry value — WIST-4
§5) regardless of Pings. A lost Ping therefore delays ingestion but never
loses data.

The `/.well-known/wist/` path is published *for* automated consumption
by Aggregators; `robots.txt` directives do not apply to fetches under
this path. This suite obliges no fetch of any other path: nothing in it
compares a page with its publication, so a Publisher's `robots.txt`
governs whatever a Labeler or a Consumer chooses to fetch on its own
account and nothing the protocol requires.

### 5.5. Labels

Whenever an Aggregator pulls a Publisher — on a Ping and at the baseline
interval alike — it MUST also fetch `label-feed.json` where the domain
serves one, walk it under §3.2's rules and the ingest budget (§5.2), fetch
`labels/<id>.json` for each ID it has not seen, validate the Label or
dispute under §3.3 and WIST-1 §4, and queue it for sealing as a `label` or
`dispute` Entry under the eligibility and inclusion ceiling of WIST-3
§3.3 and the per-Labeler cap of WIST-3 §3.2. A Label or Dispute ID
is **seen** when the Aggregator has sealed it or holds it accepted for
sealing — queued, or held under a recovery window — and not otherwise. A
Label or dispute that fails is `WIST2-E06`, a signature or key-binding
failure keeping `WIST1-E01`/`WIST1-E02` (§7), reported at the status
endpoint (§7.1) with its ID, and pulled again on the next pull and,
failing again, rejected again, the rejection recorded afresh; a listed
file that cannot be fetched, carries neither a Label nor a dispute, or
does not carry the listed ID fails the same way. The Label Feed is pulled
once the pull of every Collection has ended: a pull that stops at its
Declaration (§5.1) or suspends pulls no Label Feed in that pull. A Label
walk that cannot begin under a spent budget (§5.2) waits for the next pull
without suspending the completed Collection pulls; one that stops mid-walk
suspends and resumes as §5.2 says. The vector
`vectors/wist2/fetch-bounds.json` exercises these dispositions.

## 6. Unsigned Change Hints (Compatibility)

Aggregators MAY consume existing ecosystems as Change Hints: IndexNow
pings, sitemap `<lastmod>` changes, and llms.txt updates.

An unsigned hint MUST NOT produce content attributed to the domain.

For every URL, listed in a Catalog or not, hints only inform the
Aggregator's pull scheduling — they produce no log entries.

The signed path always has higher weight and lower latency: signed Items
enter the log on the publisher's authority, while hints are
second-class — unattributed, scheduled at the system's convenience. This
asymmetry is the adoption incentive for WIST-1/WIST-2.

## 7. Error Registry

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| WIST2-E01 | A pull stopped or a file not fetched: outside first contact, a pull stopped at its Declaration (§5.1 step 0); a `catalog.json` that cannot be fetched (§5.1 step 2, §8); a `next` that fails §3.2's target rule (§3.2). Aggregator retries with exponential backoff at 1 min, 4 min, 16 min, 64 min; a fresh ping cancels a pending backoff and starts a new attempt, subject to quota. A pull stopped at its Declaration is not noise (§4): the backoff, not the quota, is what bounds a domain that keeps serving one. |
| WIST2-E02 | Ping produced no new content: a pull that discovers no Declaration, accepts no Catalog and admits no Item, Label or dispute and neither stopped at its Declaration outside first contact nor suspended (§5.4). Counts as noise against the domain's Ping quota. |
| WIST2-E03 | An Item whose `publisher` is not its Catalog's (WIST-1 §7); an Item of kind `page` whose `payloads/<hex>.json` is missing, corrupted, or fails WIST-1 §7's Payload checks against its commitment, at the pull (§5.1 step 4) or at its turn (WIST-3 §3.3); an Item of kind `page` whose Item ID a `payload_withdrawal` names (§5.1 step 4). The Item is not admitted and the other Items proceed. Typed rejection, visible to the Publisher via the status endpoint (§7.1). |
| WIST2-E04 | First contact or authentication failure, each case an object failing to authenticate as this domain's: a first-contact pull (§5.1 step 0) whose `publisher.json` is missing, unreachable, malformed, or fails WIST-1 §5.1 or §5.2 — the case where no Key Set exists to check anything against; a Catalog that names another Publisher or Collection than the one it was fetched for (§4, WIST-1 §7), which authenticates as some other Collection's or as none, whatever key signed it; and a Page that verifies under neither source of §3.2. A first-contact failure discards the pull and counts as noise against the quota; a refused Catalog leaves the pull to §5.4. The status endpoint (§7.1) MUST distinguish the cases in its `detail` field, since a Publisher whose Declaration never loaded, one whose Catalog is misaddressed and one whose Page fails verification take entirely different remedies. |
| WIST2-E05 | Regression: a Catalog not later than its Collection's last accepted Catalog that is no idempotent re-serve (WIST-1 §7), a queued Catalog not later than the floor at settlement (WIST-1 §5.2), or a live `label-feed.json` whose `generated_at` regressed (§3.2). The Catalog or the Label Feed is discarded. The code is no noise of its own — §4's noise set is closed at `WIST2-E02`/`WIST2-E04` — and the pull resolves by §5.4. |
| WIST2-E06 | Label rejected (§3.3): a Label referenced in the Label Feed but missing or corrupted at `labels/<id>.json`; a field, version or JSON eligibility failure under WIST-1 §4 and §7's rules read over the `label` object; a `subject` that is not its own Normalized URL or Canonical Host, or exceeds `url_cap_bytes`; a `name` outside the Label Registry's form; an `asserted_at` beyond the clock allowance; a `labeler` other than the authenticated domain of the Label Feed that lists it; or a self-labeling Label. A signature or key-binding failure keeps `WIST1-E01`/`WIST1-E02`. Typed rejection, visible to the Labeler via the status endpoint (§7.1) with the Label or Dispute ID as `id`; not noise. Log replay ignores a sealed `label` or `dispute` Entry that fails one, keeping its Epoch (WIST-3 §3.3). |
| WIST2-E07 | Catalog refused whole (§5.1 step 3): its walk meets a condition of §5.3, a tree file that is not valid JCS input included (WIST-1 §4), or its list holds no Item for the URL of a record the Log holds for the Collection, which the report names. Nothing of the Catalog is sealed, and it is fetched again at the next pull. No noise of its own; the pull resolves by §5.4. |
| WIST2-E08 | Change-list chain discarded (§5.3), a change list that is not valid JCS input included (WIST-1 §4): reported with the condition met, the fetched Catalog's ID and the Catalog ID that names the change list at which it was met. Refuses nothing, adds no noise and starts no retry; the walk that follows decides the Catalog. |

### 7.1. Publisher Status Endpoint

Aggregators MUST expose `GET https://<log_id>/status/<domain>` at the
Service Origin (WIST-3 §6), returning the
`status` object (schema:
[`schemas/status.schema.json`](../schemas/status.schema.json)) as JSON. It
carries `wist_version`, the `domain` it describes, and:

- `last_pull_at` — the time of the last successful pull, or `null` if the
  Aggregator has never completed one;
- `quota_remaining` — Pings still available to the domain's Registrable
  Domain in the current UTC-day window, against the `Q` of WIST-4 §5,
  shared with every other host of that Registrable Domain (§4);
- `state` — the domain's **ingestion** state: one of `new` (known, not yet
  successfully pulled), `active`, or `refused` (the Aggregator does not
  ingest the domain — the one state §4 answers a Ping with `403` for);
- `collections` — one entry per Collection of the domain that the
  Declaration in force or the sources of the last pull name, or for which
  the Log holds a latest Catalog, with its `name`; `latest`, the Catalog
  ID of its latest Catalog (WIST-3 §7), or `null`; `accepted`, the Catalog
  ID of its last accepted Catalog (WIST-3 §3.3), or `null`; and `waiting`,
  each of its Catalogs and Items that waits, is held or is queued (WIST-1
  §5.2) once the Aggregator's last sealed Epoch has applied, with its
  `id`, an Item's `url`, `deferrals`, the deferrals of WIST-3 §3.3 that
  applied to it at that Epoch, in that section's order, named
  `recovery_window`, `capacity`, `catalog_waiting` and `latest_fails_i4`,
  and `held`, `true` where none applied and the hold of a Declaration that
  reduces authority (WIST-1 §5.2) kept it out of that Epoch;
- `rejections` — the pending typed rejections, in an order this edition
  fixes only among the Labels and disputes that leave at one Epoch
  (WIST-3 §3.3), each with its `code` (a
  WIST-1 or WIST-2 error code, §7 and WIST-1 §7), the `at` it was
  recorded, a free-text `detail`, and where one applies: `id`, the ID of
  the object it concerns — a Declaration's
  `"sha256:" + hex(SHA-256(JCS(publisher)))` (WIST-1 §5.2), a Catalog ID,
  an Item ID, a Label ID or a Dispute ID; `collection`, the name of the
  Collection of a Catalog or an Item; `urls`, the URL of an Item, or every
  URL a Catalog refused for a list that drops a record's URL fails to list
  (§5.1 step 3); and for `WIST2-E08`, `condition`, one of `fetch`, `size`,
  `form`, `chain` and `result`, beside `id`, the fetched Catalog's ID, and
  `change_list`, the Catalog ID that names the change list at which the
  condition was met (§5.3).

The status document is a plain JSON object, not a signed Envelope — it is
the Publisher's debugging surface, not an artifact other parties verify.

## 8. Security Considerations

- **Ping flooding.** Pings are the cheapest object in the system by
  design: no content, no crypto, one small POST. Amplification is
  bounded, not minimal by nature: in steady state a Ping triggers
  conditional fetches of the Declaration and of each Collection's
  `catalog.json` and, where a Catalog changed, a change list, but a first
  contact obliges the walk of every Collection's tree and the Label walk,
  whose size the pinging domain controls — which is why §5.2's
  per-domain ingest budget, not the Ping's own cheapness, is the
  content-walk bound; Declaration requests are excluded (§5.2). Quotas
  (WIST-4 §5) throttle abusive domains, and both the quota and the
  budget are keyed per Registrable Domain (WIST-4 §3.1), so a flood
  from a thousand free hostnames under one name is one domain's flood;
  Ingest Endpoints SHOULD additionally apply source-IP rate limits below the
  per-domain quotas.
- **Replay.** An attacker replaying an old `catalog.json` cannot regress
  state: the signature binds the Catalog, a pull refuses one not later
  than the last accepted Catalog (`WIST2-E05`, WIST-1 §7), and the Log
  ignores one not later than the floor (WIST-3 §3.3). A replayed
  `label-feed.json` meets §3.2's `generated_at` monotonicity, and Labels
  already seen are idempotent (§5.5).
- **Cache poisoning of `.well-known`.** All discovery and pulls are
  HTTPS-only; Aggregators MUST NOT accept any `wist` resource
  over plain HTTP. An Aggregator MUST follow a redirect only when the
  target is `https` and its Canonical Host equals the Canonical Host of
  the request, or is listed in the Publisher's `subdomain_scope`.
  Apex-to-`www` redirects are therefore conforming when `www` is in
  scope. The target rule bounds *where* a chain can go and not how long
  it runs, and two in-scope hosts pointing at each other satisfy it for
  ever, so two bounds close the chain: an Aggregator MUST NOT follow a
  redirect to a URL already fetched in the same chain, and MUST NOT
  follow more than five in one. A resource whose chain exceeds either is
  not retrieved, which is a failed fetch with the disposition this
  document gives that resource. Five is chosen rather than derived: a
  publication path needing a sixth hop to reach its own well-known file
  is misconfigured rather than unlucky.
- **Redirect authority per request.** The `subdomain_scope` a redirect
  target is checked against is the one in the Declaration accepted at
  the instant the request is issued: a replacement accepted earlier in
  the same pull governs the requests after it, and a host the
  replacement dropped no longer authorizes a redirect. Before the first
  accepted Declaration — during first contact (§5.1) — a redirect MUST
  stay on the requested Canonical Host.
- **Fetch destinations.** A Publisher chooses where every fetch goes —
  its Canonical Host, each redirect target and the addresses its names
  resolve to — so an Aggregator's fetcher is a request an outside party
  aims from inside the Aggregator's network. An Aggregator MUST connect
  only to a public unicast address: it checks a literal host, every
  redirect hop and every address a name resolves to at connection time,
  and refuses a name whole when any address it resolves to is refused.
  The refused classes are, for IPv4, loopback (127.0.0.0/8), unspecified
  (0.0.0.0), private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
  link-local (169.254.0.0/16, where cloud metadata services live),
  shared address space (100.64.0.0/10), broadcast (255.255.255.255),
  multicast (224.0.0.0/4), documentation (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24), benchmarking (198.18.0.0/15) and reserved
  (240.0.0.0/4); for IPv6, loopback (::1), unspecified (::), unique
  local (fc00::/7), link-local (fe80::/10), multicast (ff00::/8) and
  documentation (2001:db8::/32); an IPv4-mapped (::ffff:0:0/96), 6to4
  (2002::/16) or NAT64 (64:ff9b::/96) address takes the class of the
  IPv4 address it embeds. A deployment that runs the whole stack on one
  machine MAY admit loopback alone, under the same explicit opt-in that
  admits plain HTTP to it. A refused destination is a failed fetch, with
  the disposition this document gives the object that cannot be fetched.
- **Response bounds.** No field check applies before an object has been
  read, so the octets an Aggregator reads are bounded before the fields
  are. An Aggregator MUST NOT read more than 1 048 576 octets of a
  Declaration, Label Feed, Page or Mirror list (WIST-3 §5); 16 384 octets
  of `catalog.json`; `change_list_cap_bytes` octets of a change list
  (§3.1); 16 384 + 2 × `url_cap_bytes` octets of a Label or dispute file
  (§3.3); or `extract_cap_bytes` +
  `links_cap_bytes` + `summary_cap_bytes` + 4 096 octets of a Payload,
  each parameter read from the map in force at the request (WIST-4 §5).
  The fixed terms cover what the caps do not reach — signatures,
  identifiers, timestamps, framing and the Payload salt — and the flat
  bounds cover objects whose fields the schema bounds by count and
  length rather than by a parameter. An object above its bound is a
  failed fetch with the dispositions above. The octets of `catalog.json`
  need only be valid JCS input, not the JCS serialization, since the
  Entry carries the Envelope they parse to. A tree file's own response
  bound is the `tree_file_cap_bytes` in force for that request (§5.3): an
  Aggregator reads at most that bound plus one octet of it, and a tree
  file above it refuses its Catalog with `WIST2-E07` and debits nothing,
  as §5.2 gives for an object above its own bound. The vector
  `vectors/wist2/fetch-bounds.json` exercises this rule and the two
  before it. See [ADR-0044](../decisions/0044-fetch-bounds.md).

## 9. Privacy Considerations

Pings reveal publication timing to the Aggregator, and Catalogs, tree
files, change lists and Label Feeds are public by construction — a
Publisher's activity pattern is observable by anyone, and a change list
states which Items differ between two Catalogs. No reader or consumer data
is involved at this layer: WIST-2 concerns only the Publisher→Aggregator
direction, and Publishers learn nothing about who consumes their
publications.

## 10. Conformance Checklist

This checklist is not the document's last section: §11 defines the link
extraction procedure the Publisher row below is stated over, and it
follows here rather than preceding it so that the pull sequence stays
adjacent to the layout it walks.

**Publisher:**

- [ ] Serves the well-known paths over HTTPS with the layout of §3
- [ ] Serves each Collection's Catalog at `catalog.json`, and every tree
      file and Payload it names, written before the Catalog is served,
      tree files named by the SHA-256 of their octets and Payloads by the
      Item ID (§3.1)
- [ ] Writes the change list of each Catalog signed over a served one,
      unless it would exceed `change_list_cap_bytes`, and serves the
      first `change_chain_max` change lists of the served Catalog's chain
      (§3.1)
- [ ] Keeps serving for `replaced_file_seconds` a file a replaced Catalog
      named, a change list put out of the chain and the files of a
      Collection the served Declaration stopped naming (§3.1)
- [ ] Declares `content.links` from the emitted content as WIST-1 §3.6
      gives, by §11's procedure for an HTML fragment, truncated to the
      longest prefix that fits `links_cap_bytes` (§11, WIST-1 §3.6)
- [ ] Stops serving a Payload from the height a `payload_withdrawal`
      naming its Item is sealed — the serving duty above does not
      survive it — whatever Catalog names it (§3.1, WIST-3 §6.2)
- [ ] Where it labels, serves each Label at `labels/<id>.json` and lists
      it in its Label Feed under §3.2's rules, signs it under its Key Set,
      names a registry `name`, places `expires_at` after `asserted_at`,
      binds `delta` only to a URL subject, and never labels a subject
      under its own authority (§3.3)
- [ ] Where it labels, serves a signed definition of each name it uses
      at `labels/definitions/<hex>.json` with a description URL and a
      treatment (§3.3)
- [ ] Where it disputes, serves each dispute at `labels/<id>.json`,
      lists it in a Label Feed, names a sealed Label whose subject lies
      under its own authority, and signs it under its Key Set (§3.3)
- [ ] Seals Pages when `deltas` would exceed 1000 entries — file
      published before cutover, sealing-order numbering, no ID omitted or
      duplicated across Pages, monotonic `generated_at` (§3.2)
- [ ] Pings with the exact one-field body of §4, honors `Retry-After`, and
      follows the retry/backoff rule of §4

**Aggregator (ingest side):**

- [ ] Fetches the Declaration at the start of every pull, judges an answer
      304 as the Declaration it validates, and pulls nothing more where
      the fetch fails: `WIST2-E04` at first contact, which is noise, and
      `WIST2-E01` after it, which is not (§5.1, §5.4)
- [ ] Pulls each Collection the pull's sources name, in their order,
      reading at most 16 384 octets of `catalog.json` and judging it by
      WIST-1 §7's Catalog conditions, order and idempotent re-serve (§5.1,
      §8)
- [ ] Obtains an accepted Catalog's list from a held list, from change
      lists or by the walk; discards a chain at the first condition of
      §5.3 it meets, reporting `WIST2-E08`, and walks after it; refuses a
      Catalog whose walk fails with `WIST2-E07`, stopping the walk at the
      first failure and fetching no child of an inner file that fails a
      rule read from that file alone (§5.3)
- [ ] Refuses with `WIST2-E07`, naming every such URL, a list that holds
      no Item for the URL of a record its Log holds and the Scope covers,
      unless the Catalog is a base (§5.1)
- [ ] Admits an Item only under the Item conditions and, for an Item of
      kind `page` that is not its record's, with its Payload verified;
      reports `WIST2-E03` for a missing or failing Payload and for a
      withdrawn Item, whose Payload it does not fetch (§5.1, §7)
- [ ] Judges again the Items not admitted at every pull that accepts a
      Catalog or meets an idempotent re-serve (§5.1)
- [ ] Applies the per-domain ingest budget, accounted per Registrable
      Domain, suspending and resuming rather than truncating, with no
      Declaration request debited (§5.2, WIST-4 §3.1)
- [ ] Follows `next` through a Label Feed's sealed Pages until reaching an
      already-seen ID or `null`; reads `next` only when the walk
      continues; fetches a target only when byte-identical to its
      Normalized URL and beginning with `https://`, the requested
      Canonical Host and `/.well-known/wist/`, otherwise recording
      `WIST2-E01`, fetching nothing there and keeping the IDs already
      fetched (§3.2)
- [ ] Verifies a sealed Page against the Key Set current at its
      `generated_at`, or that of the first Epoch after it sealing an
      applicable Declaration — the highest `seq`'s where an Epoch seals
      several (§3.2)
- [ ] Runs baseline polling independent of Pings (§5.4)
- [ ] Pulls a domain's Label Feed after its Collections under the same
      budget, validates each Label and dispute under §3.3 — a dispute only
      of a Label it has sealed whose subject lies under the disputant's
      authority — seals what verifies under the per-Labeler cap and
      reports `WIST2-E06` for the rest, or `WIST1-E01`/`WIST1-E02` for a
      signature or key-binding failure (§3.3, §5.5, §7, WIST-3 §3.2)
- [ ] Never attributes unsigned-hint content to a domain (§6)
- [ ] Implements the Error Registry behaviors and the status endpoint,
      with its Collections and the members of its rejections (§7, §7.1)
- [ ] Accounts pings correctly against the Registrable Domain's quota
      under the snapshot in force — only `WIST2-E02`/`WIST2-E04` count
      as noise (§4, §5.4, WIST-4 §3.1)
- [ ] HTTPS-only, same-authority-only fetching, per the Canonical Host /
      `subdomain_scope` redirect rule (§8)

## 11. Link Extraction

This procedure gives a publication's `links` member (WIST-1 §3.6). For
an Emission (WIST-5) of `html`, steps 1 to 8 read the UTF-8 octets of
`html`. For an Emission of `text`, each member of its `links` array is,
in array order, a candidate that passes the trim ending step 4 and then
steps 5 to 8; character references in it are not decoded. A party that
chooses to compare a served page with a publication runs steps 1 to 8 on
the page's raw response octets; nothing in this suite obliges that
comparison. The procedure is deterministic, so that two tools deriving a
publication from the same content declare the same links. It reads
octets, never a DOM after script execution: a link that script inserts
does not exist for it.

Steps 1 to 3 are one left-to-right scan. At each octet where one of them
opens a construct, that construct is consumed whole, and nothing inside
it is matched by another step: a `<!--` inside an `a` start tag opens no
comment, and an `<a` inside a comment or a raw-text element opens no
tag. A `<!--` inside a tag that opens no construct of this scan, such as
`<div title="<!--">`, opens a comment. At every other octet the scan
advances by one. Names are compared with the ASCII letters A to Z folded
to a to z and no other octet folded. **Whitespace** in this section is
tab, LF, FF, CR and space (0x09, 0x0A, 0x0C, 0x0D, 0x20).

1. A comment opens at `<!--` and runs through the first `-->` that begins
   after that `<!--`, or through the end of input where there is none;
   `<!-->` and `<!--->` close nothing.
2. A raw-text element opens at `<script`, `<style` or `<textarea`
   immediately followed by whitespace, `/`, `>` or the end of input;
   `<scripts` opens none. Its start tag ends by step 3's attribute rule,
   read from the octet after the element name. The element runs from
   that start tag up to the first `</script`, `</style` or `</textarea`,
   respectively, after the start tag's end, whatever octet follows that
   name, or through the end of input where there is none. The scan
   resumes at that `</`.
3. An `a` start tag opens at `<a` immediately followed by whitespace,
   `/`, `>` or the end of input; `<article>` and `<aside>` MUST NOT
   match. Its attributes are read from the octet after `a` by the
   **attribute rule**: whitespace and `/` between attributes are skipped.
   An attribute name is a run, possibly empty, of octets other than
   whitespace, `=`, `>` and `/`, and whitespace may follow it. An
   optional `=`, which whitespace may follow, introduces the value: a
   value opening with `"` or `'` is quoted and runs to the next octet
   equal to that quote, or to the end of input where there is none; any
   other value is a run, possibly empty, up to the next whitespace or
   `>`. A quote anywhere else, in a name or inside an unquoted value, is
   an ordinary octet. An attribute without `=` has the empty value. The
   tag ends after the first `>` met outside a quoted value, or at the end
   of input, and a tag that reaches the end of input counts. The
   candidate is the value of the first attribute named `href`;
   `data-href` is a different attribute and MUST NOT be treated as
   `href`. A tag without an `href` attribute yields no candidate.
4. A candidate whose octets are not well-formed UTF-8 is discarded.
   Character references in the candidate are then decoded in one
   left-to-right pass whose output is not decoded again (`&amp;lt;` gives
   `&lt;`): `&amp;`, `&lt;`, `&gt;`, `&quot;` and `&apos;`, spelled in
   lowercase; and `&#NNN;` and `&#xHH;`, where `NNN` is one or more of
   the ASCII digits `0`-`9`, `x` is lowercase, and `HH` is one or more of
   `0`-`9`, `A`-`F` and `a`-`f`, of any length and with any leading
   zeros, each standing for the code point its digits denote. The digit
   repertoires are pinned because a language whose digit class spans
   Unicode decodes `&#٦٥;` to `A`, which this step leaves as written. An
   `&` that begins none of these references, `&AMP;` and `&#X41;`
   included, is left as written. A numeric reference whose code point is not a Unicode scalar
   value — above 0x10FFFF, or a surrogate 0xD800 to 0xDFFF — discards the
   candidate, the fail-closed posture WIST-1 §2 takes toward an
   unresolvable escape. Last, every leading and trailing whitespace
   character, whether written or decoded from a reference, is removed
   from the candidate, and no other character is: a candidate that
   begins with U+00A0 keeps it.
5. Resolve the candidate per RFC 3986 §5 against the Emission's URL, or,
   for a served page, against the final response URL.
6. Normalize per WIST-1 §2. A candidate with no Normalized URL is not a
   link and is discarded (WIST-1 §2), and so is a link whose `JCS`
   serialization exceeds `link_url_cap_bytes` (WIST-1 §3.6).
7. Discard every link whose Canonical Host is the Publisher's domain or
   a subdomain of it.
8. Deduplicate: the first occurrence of a Normalized URL holds its
   position; later occurrences are discarded.

The count of survivors is `total`. `urls` is the longest prefix of the
survivors, in order, whose serialized `links` object fits
`links_cap_bytes` (WIST-1 §3.6).

**Which representations are HTML.** A served representation is **HTML**
for this suite when the media type of its `Content-Type` response header
— compared case-insensitively, with any parameters such as `charset`
ignored — is `text/html` or `application/xhtml+xml`. Every other media
type is not, and neither is a representation served with no
`Content-Type`. A served representation that is not HTML has no links
under this procedure. The question is decided from that header alone,
never by sniffing the body, so that every party that fetches the
representation reads it the same way; the predicate is enumerated rather
than left to "whatever a browser would parse" because two tools that
read `application/xhtml+xml` differently would derive different sets
from one page.

`vectors/wist2/link-extraction.json` carries fixtures over a page's
octets: one whose full set exceeds the budget, so that the prefix rule
is exercised, one holding a link above `link_url_cap_bytes`, and one
exercising the scan — a comment-wrapped link, a script-embedded link, a
`data-href` decoy, a quoted attribute value containing `>`, a character
reference, an uppercase tag and an unquoted `href`.
`vectors/wist5/emission-derivation.json` carries both Emission forms,
the trim included.

## 12. Text Extraction

This procedure derives text from HTML octets. It gives the `extract`
(WIST-1 §3.6) of an Emission (WIST-5) of `html`, read from the UTF-8
octets of `html`; the `extract` of an Emission of `text` is `text`,
unchanged. A party that chooses to compare a served page with a
publication applies it to the page's raw response octets, where its
output is the page's **observed text**; that comparison should read
containment — how much of the published text the page carries — since a
whole page carries its navigation and footer. The procedure reads its
whole input: a rule isolating "main content" would be a boilerplate
heuristic, and heuristics are the disagreement this section exists to
remove; a Publisher selects its content by what it emits. It reads
octets, never a DOM:

1. Remove every comment and every raw-text element by one left-to-right
   scan of §11 steps 1 and 2 alone, each removed construct leaving a
   single space (0x20). No tag is a construct of this scan, so a `<!--`
   opens a comment, and a raw-text start tag opens its element, anywhere
   outside a comment or a raw-text element, inside any tag included.
   Inside an `a` start tag this differs from §11, which consumes that
   tag whole: §11 and this procedure can read the same octets
   differently there. The end tag of a raw-text element is not removed;
   step 2 reads it as a tag.
2. Replace each tag in what step 1 leaves with a single space. A tag
   opens at `<` immediately followed by an ASCII letter, `/`, `!` or
   `?`, and is read from the octet after that `<` by §11 step 3's
   attribute rule, the element name reading as an attribute name; it
   ends where that rule ends a tag. A `<` followed by anything else is
   literal text. Everything outside tags is literal text.
3. Decode the resulting octet stream as UTF-8, replacing each maximal
   subpart of an ill-formed subsequence (Unicode 16.0 §3.9, "U+FFFD
   Substitution of Maximal Subparts") with one U+FFFD: `F0 80 80` gives
   three U+FFFD, and `E2 82 41` gives one U+FFFD then `A`. The declared
   charset is never consulted: charset sniffing is
   implementation-divergent, and a non-UTF-8 page degrades identically
   for every implementation. The octets of an Emission's `html` are
   well-formed UTF-8 (WIST-5), so this step replaces nothing in them.
4. Decode character references in the text with §11 step 4's
   repertoire, in one pass as there; a reference whose code point is
   not a Unicode scalar value is left exactly as written, since text is
   not a link candidate and there is nothing to fail closed on.
5. Collapse every run of ASCII whitespace (tab, LF, FF, CR, space) to
   a single space and trim the ends.

Every choice above that departs from rendering — inline tags becoming
word boundaries, a declared charset ignored — departs identically for
every implementation, which is the property that matters.
`vectors/wist2/text-extraction.json` carries the conformance fixtures
for this procedure.

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- WIST-1: Item Format & Identity — Items, Catalogs, tree files, Envelope,
  Key Set, Collections and Scopes
- WIST-3: Logbook & Distribution — sealing, waiting and records
- WIST-4: Governance & Parameters — quotas, parameters, the Label Registry
- WIST-5: Emissions — how a Publisher derives and signs its Catalogs
