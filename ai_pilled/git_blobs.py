"""Bounded Git batch reads for an ordered list of index blobs."""
from .runtime import CommandError, run

MAX_BATCH_BYTES = 2_100_000


def batch_contents(repo, batch):
    request = b''.join(oid.encode() + b'\n' for _, oid, _ in batch)
    limit = sum(size + len(oid) + len(str(size)) + 8 for _, oid, size in batch)
    output = run(['git', 'cat-file', '--batch'], repo, input_data=request, limit=limit)
    position = 0
    results = []
    for path, oid, size in batch:
        header = f'{oid} blob {size}\n'.encode()
        if output[position:position + len(header)] != header:
            raise CommandError('Cannot read the expected staged blob')
        position += len(header)
        content = output[position:position + size]
        position += size
        if len(content) != size or output[position:position + 1] != b'\n':
            raise CommandError('Incomplete staged blob batch')
        position += 1
        results.append((path, content, None))
    if position != len(output):
        raise CommandError('Unexpected data after staged blob batch')
    return results


def read_blobs(repo, sources, maximum):
    """Yield path/content/error in source order, with bounded live content bytes."""
    if not sources:
        return
    identifiers = list(dict.fromkeys(oid for _, oid in sources))
    request = ''.join(oid + '\n' for oid in identifiers).encode()
    try:
        output = run(['git', 'cat-file', '--batch-check'], repo, input_data=request)
        rows = output.decode('ascii').splitlines()
        if len(rows) != len(identifiers):
            raise CommandError('Incomplete staged blob metadata')
        sizes: dict[str, int | None] = {}
        for oid, row in zip(identifiers, rows):
            fields = row.split()
            if fields == [oid, 'missing']:
                sizes[oid] = None
            elif len(fields) == 3 and fields[:2] == [oid, 'blob'] and fields[2].isdigit():
                sizes[oid] = int(fields[2])
            else:
                raise CommandError('Invalid staged blob metadata')
    except (CommandError, ValueError) as exc:
        error = str(exc) if isinstance(exc, CommandError) else 'Invalid staged blob metadata'
        for path, _ in sources:
            yield path, None, error
        return

    def read_batch(batch):
        try:
            return batch_contents(repo, batch)
        except CommandError as exc:
            return [(path, None, str(exc)) for path, _, _ in batch]

    pending: list[tuple[str, str, int]] = []
    total = 0
    for path, oid in sources:
        size = sizes[oid]
        cost = size + len(oid) + len(str(size)) + 8 if size is not None else 0
        if pending and (size is None or size > maximum or total + cost > MAX_BATCH_BYTES):
            yield from read_batch(pending)
            pending, total = [], 0
        if size is None:
            yield path, None, 'Staged blob is unavailable'
        elif size > maximum:
            yield path, None, 'File exceeds scan size limit'
        else:
            pending.append((path, oid, size))
            total += cost
    if pending:
        yield from read_batch(pending)
