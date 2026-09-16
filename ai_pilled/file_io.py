"""Bounded regular-file reads and root-relative directory access."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

from .runtime import CommandError


@contextmanager
def open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CommandError('Input must be a regular file')
        yield stream


@contextmanager
def directory_beneath(root, name, *, create=False):
    """Hold a root-relative directory descriptor without following symlinks."""
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise CommandError('Directory path must stay beneath its root')
    directories = []
    try:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directories.append(parent)
        for component in relative.parts:
            if create:
                try:
                    os.mkdir(component, 0o755, dir_fd=parent)
                except FileExistsError:
                    pass
            parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            directories.append(parent)
        yield parent
    finally:
        for descriptor in reversed(directories):
            os.close(descriptor)


@contextmanager
def open_beneath(root, name):
    """Open a regular repository file without following any relative symlink."""
    relative = Path(name)
    if relative.is_absolute() or not relative.parts or '..' in relative.parts:
        raise CommandError('Input path must stay beneath its root')
    directories = []
    try:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directories.append(parent)
        for component in relative.parts[:-1]:
            parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            directories.append(parent)
        fd = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        for directory in reversed(directories):
            os.close(directory)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CommandError('Only regular files can be read')
        yield stream


def read_regular(path, maximum):
    with open_regular(path) as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise CommandError('Input exceeds the configured size limit')
    return content


def file_identity(metadata):
    """Metadata identity excluding access time, which reads may update."""
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_mode)


def read_beneath(root, name, maximum):
    """Read bounded root-relative evidence, rejecting observed identity changes."""
    with open_beneath(root, name) as stream:
        before = file_identity(os.fstat(stream.fileno()))
        content = stream.read(maximum + 1)
        after = file_identity(os.fstat(stream.fileno()))
    if len(content) > maximum:
        raise CommandError('Input exceeds the configured size limit')
    if before != after:
        raise CommandError('Input changed while reading; rerun after reviewing edits')
    with open_beneath(root, name) as current:
        if file_identity(os.fstat(current.fileno())) != before:
            raise CommandError('Input was replaced after reading; rerun after reviewing edits')
    return content


def read_snapshot(path, maximum, *, root=None):
    """Read bounded bytes plus descriptor identity, distinguishing an absent file."""
    try:
        opening = open_regular(path) if root is None else open_beneath(root, Path(path).relative_to(root))
        with opening as stream:
            before = file_identity(os.fstat(stream.fileno()))
            content = stream.read(maximum + 1)
            after = file_identity(os.fstat(stream.fileno()))
    except FileNotFoundError:
        return None, None
    if len(content) > maximum:
        raise CommandError('Input exceeds the configured size limit')
    if before != after:
        raise CommandError('Input changed while reading; rerun after reviewing edits')
    if root is not None:
        try:
            with open_beneath(root, Path(path).relative_to(root)) as current:
                if file_identity(os.fstat(current.fileno())) != after:
                    raise CommandError('Input was replaced after reading; rerun after reviewing edits')
        except OSError as exc:
            raise CommandError('Input became unavailable after reading; rerun after reviewing edits') from exc
    return content, after
