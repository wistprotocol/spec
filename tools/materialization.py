import hashlib

import rfc8785

import collection_rules as rules
import items


def preferred(host, declared, publishers):
    if declared:
        return host if host in publishers else None
    ancestors = [p for p in publishers if host.endswith("." + p)]
    if ancestors:
        return max(ancestors, key=len)
    return min(publishers, key=str.encode) if publishers else None


def content_tuple(publisher, url, item, attested_at):
    return {"url": url, "publisher": publisher, "item_id": items.item_id(item),
            "observed_at": item["observed_at"], "attested_at": attested_at}


def materialized(records, declared, withdrawn):
    by_url = {}
    for (publisher, url), record in records.items():
        if items.item_id(record["item"]) not in withdrawn:
            by_url.setdefault(url, {})[publisher] = record
    out = []
    for url, held in by_url.items():
        host = rules.url_host(url)
        chosen = preferred(host, host in declared, list(held))
        if chosen is not None:
            out.append(content_tuple(chosen, url, held[chosen]["item"], held[chosen]["generated_at"]))
    return sorted(out, key=lambda t: (t["url"].encode(), t["publisher"].encode()))


def content_digest(tuples):
    return "sha256:" + hashlib.sha256(b"".join(sorted(rfc8785.dumps(t) for t in tuples))).hexdigest()
