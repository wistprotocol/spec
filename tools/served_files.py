import items

REPLACED_FILE_SECONDS = 86400


def must_serve(served, stop, clock):
    if not served:
        return []
    instants = [items.instant(catalog["served_at"]) for catalog in served]
    now = items.instant(clock)
    if any(later < earlier for earlier, later in zip(instants, instants[1:])) or now < instants[-1]:
        raise ValueError("Catalogs must be served in order and the clock at or after the last")
    named = set(served[-1]["files"])
    out = set(named)
    for name in {f for catalog in served for f in catalog["files"]} - named:
        last = max(i for i, catalog in enumerate(served) if name in catalog["files"])
        if now < instants[last + 1] + REPLACED_FILE_SECONDS:
            out.add(name)
    return sorted(out - set(stop), key=str.encode)
