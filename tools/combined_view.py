import catalogs


def order_key(generated_at, catalog_id):
    return catalogs.log_seconds(generated_at), catalog_id.encode()


def catalog_key(catalog):
    return order_key(catalog["generated_at"], catalogs.catalog_id(catalog))


def in_catalog_order(listed):
    return sorted(listed, key=catalog_key)


def state_key(state):
    return order_key(state["generated_at"], state["catalog"])


def combined_state(states):
    held = {log: state for log, state in states.items() if state is not None}
    if not held:
        return None
    latest = max(held.values(), key=lambda state: (state_key(state), state["item"].encode()))
    logs = sorted(log for log, state in held.items()
                  if state_key(state) == state_key(latest) and state["item"] == latest["item"])
    return {"state": latest, "logs": logs}
