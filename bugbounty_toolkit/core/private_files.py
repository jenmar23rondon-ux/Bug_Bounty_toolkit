"""Bounded local I/O and atomic, private publication for offline artifacts.

POSIX directory descriptors pin every ancestor; unsafe links are never followed.
Private publication fails closed on platforms without these primitives.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import stat
from typing import Iterator


def local_path(path: Path) -> Path:
    text = str(path)
    if len(text) > 4096 or ".." in path.parts or "\\" in text or "://" in text or text.startswith("//"):
        raise ValueError("Use a bounded local path without traversal or network components.")
    path = path.expanduser().absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Local artifact paths must not contain symbolic links.")
    return path


@contextmanager
def _parent(path: Path, create: bool = False) -> Iterator[int]:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Secure offline artifact I/O requires POSIX no-follow directory descriptors.")
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def read_private_input(path: Path, limit: int, *, protected: bool = False) -> bytes:
    """Regular-file read with size limits; protected keys must be owned and mode 0600."""
    try:
        path = local_path(path)
        with _parent(path) as parent:
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(descriptor, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                    raise ValueError("Offline input must be a bounded regular file.")
                if protected and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ValueError("Local HMAC keys must be owned by this user with mode 0600.")
                value = handle.read(limit + 1)
        if len(value) > limit:
            raise ValueError("Offline input exceeds its byte limit.")
        return value
    except OSError as exc:
        raise ValueError("Cannot securely read the local offline input.") from exc


def atomic_private_write(path: Path, data: bytes, *, force: bool = False) -> None:
    """Publish complete mode-0600 files, exclusively by default, without following links."""
    try:
        path = local_path(path)
        with _parent(path, create=True) as parent:
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                info = None
            if info is not None and (not force or not stat.S_ISREG(info.st_mode)):
                raise ValueError("Offline output already exists or is not a regular file.")
            temporary = ".bbtk-" + secrets.token_hex(16)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                if force:
                    os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                else:
                    os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                os.fsync(parent)
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
    except OSError as exc:
        raise ValueError("Cannot atomically publish the private offline artifact.") from exc
