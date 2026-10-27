"""Decompile many classes with one APK pass.

``getclass`` reopens the APK and re-inflates DEX entries for every class. This
module inflates each DEX once, indexes the classes it defines, then decompiles
from those in-memory buffers.
"""
import mmap
import os
import re

from droidasc.asc_client.apk.dex_reader import list_dex_classes
from droidasc.asc_client.apk.loader import _inflate_dex, _parse_cd_dex_entries
from droidasc.asc_client.asc_handler import AscHandler
from droidasc.asc_client.dex_container import iter_logical_dex_buffers


def _to_dalvik_class(name):
    if not name:
        raise ValueError("Class name cannot be empty")
    name = name.strip()
    if name.startswith("L") and name.endswith(";") and "/" in name:
        return name
    name = name.replace(".", "/")
    if not name.startswith("L"):
        name = "L" + name
    return name if name.endswith(";") else name + ";"


# Characters that are path separators or invalid on common filesystems.
_UNSAFE_PATH_CHARS = re.compile(r'[\\:*?"<>|\x00-\x1f]')


def class_output_path(dalvik_class):
    """Map a Dalvik class name to a relative ``.java`` path.

    Class names come from the APK and are attacker controlled: a descriptor such
    as ``L../../x;`` must not escape the output directory, so every path
    component is sanitized and ``.``/``..``/empty components are neutralized.
    """
    inner = dalvik_class
    if inner.startswith("L") and inner.endswith(";"):
        inner = inner[1:-1]
    parts = []
    for part in inner.split("/"):
        part = _UNSAFE_PATH_CHARS.sub("_", part)
        if not part.strip("."):
            part = "_" * max(len(part), 1)
        parts.append(part)
    return os.path.join(*parts) + ".java"


def assign_output_paths(names):
    """Give every class a distinct relative output path.

    Obfuscated APKs routinely define classes differing only by case (``a/A`` and
    ``a/a``). On case-insensitive filesystems (macOS, Windows) those would
    overwrite each other, and ``--resume`` would then skip the second class, so
    later collisions get a ``~N`` suffix. ``~`` cannot occur in a Dalvik simple
    name, so a suffixed path never collides with a real class. Pass the names in
    a stable order so the mapping is the same across resumed runs.
    """
    paths = {}
    used = set()
    for name in names:
        path = class_output_path(name)
        if path.casefold() in used:
            stem = path[: -len(".java")]
            n = 1
            while f"{stem}~{n}.java".casefold() in used:
                n += 1
            path = f"{stem}~{n}.java"
        used.add(path.casefold())
        paths[name] = path
    return paths


def index_apk(apk_path, prefix=None, log=None):
    if prefix is not None:
        prefix = prefix.strip()
        if not prefix:
            raise ValueError("Class prefix cannot be empty")
        if not prefix.startswith("L"):
            prefix = "L" + prefix.replace(".", "/")
    prefix_bytes = prefix.encode("ascii") if prefix and prefix.isascii() else None

    index = {}
    with open(apk_path, "rb") as fp:
        mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            entries = _parse_cd_dex_entries(mm)
            if not entries:
                raise ValueError("No DEX entries found in APK")
            for entry in entries:
                data = _inflate_dex(mm, entry)
                if data is None:
                    continue
                for logical_name, buf in iter_logical_dex_buffers(entry[0], data):
                    if log is not None:
                        log(f"[APK] '{logical_name}' inflated={len(buf)} bytes")
                    try:
                        names = list_dex_classes(buf, prefix=prefix, prefix_bytes=prefix_bytes)
                    except ValueError:
                        # A malformed sibling DEX must not hide the classes that are fine.
                        continue
                    for name in names:
                        index.setdefault(name, buf)
            return index
        finally:
            mm.close()


def read_class_list(path):
    names = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            name = line.strip()
            if name and not name.startswith("#"):
                # a class listed twice is decompiled once
                names.setdefault(_to_dalvik_class(name), None)
    if not names:
        raise ValueError(f"{path}: no class names found")
    return list(names)


def decompile(index, dalvik_class):
    return AscHandler().getclass(index[dalvik_class], dalvik_class)


def write_source(dest, source):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8", errors="replace", newline="\n") as fp:
        fp.write(source)
        if not source.endswith("\n"):
            fp.write("\n")
