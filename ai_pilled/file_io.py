"""Bounded reads of regular input files without following the final symlink."""
import os
import stat

from .runtime import CommandError


def read_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CommandError('Input must be a regular file')
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise CommandError('Input exceeds the configured size limit')
    return content
