def decode_raw_fixture(data, bound):
    if data[:4] != bytes.fromhex("28b52ffd"):
        raise ValueError("standard frame magic required")
    position = 4

    def take(count):
        nonlocal position
        end = position + count
        if end > len(data):
            raise ValueError("truncated frame")
        value = data[position:end]
        position = end
        return value

    descriptor = take(1)[0]
    if descriptor & 8:
        raise ValueError("reserved frame bit")
    single = bool(descriptor & 32)
    if not single:
        window_descriptor = take(1)[0]
        window_base = 1 << (10 + (window_descriptor >> 3))
        window = window_base + (window_base >> 3) * (window_descriptor & 7)
    dictionary_size = (0, 1, 2, 4)[descriptor & 3]
    if int.from_bytes(take(dictionary_size), "little"):
        raise NotImplementedError("fixture requires a dictionary")
    size_width = (1 if single else 0, 2, 4, 8)[descriptor >> 6]
    if not size_width:
        raise ValueError("missing content size")
    size = int.from_bytes(take(size_width), "little")
    if size_width == 2:
        size += 256
    if size > bound:
        raise ValueError("excessive content size")
    block_maximum = min(size if single else window, 131072)
    decoded = bytearray()
    while True:
        header = int.from_bytes(take(3), "little")
        kind, count = (header >> 1) & 3, header >> 3
        if kind == 3 or count > block_maximum:
            raise ValueError("invalid data block")
        if kind == 2:
            raise NotImplementedError("fixture uses entropy compression")
        if len(decoded) + count > size:
            raise ValueError("false content size")
        if kind == 0:
            decoded.extend(take(count))
        else:
            decoded.extend(take(1) * count)
        if header & 1:
            break
    if descriptor & 4:
        raise NotImplementedError("fixture uses a checksum")
    if position != len(data) or len(decoded) != size:
        raise ValueError("trailing data or false content size")
    return bytes(decoded)
