#!/usr/bin/env python3
"""Audit a PE32+ binary for Windows 7 x64 loadability.

Checks:
  - PE32+ (64-bit)
  - subsystem version is 6.0 or 6.1 (not 6.2+ / Win8)
  - no CopyFile2 / CreateFile2 imports
  - no VC++ dynamic CRT (vcruntime140 / msvcp140) if /MT was requested
  - no api-ms-win-crt-* (Universal CRT forwarders Win7 does not ship)
"""
from __future__ import annotations

import pathlib
import struct
import sys

FORBIDDEN_IMPORT_NAMES = {
    "CopyFile2",
    "CreateFile2",
}

FORBIDDEN_DLLS = {
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "ucrtbase.dll",
}


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def _read_cstr(data: bytes, off: int) -> str:
    end = data.find(b"\0", off)
    if end < 0:
        end = min(off + 256, len(data))
    return data[off:end].decode("ascii", errors="replace")


class PeError(Exception):
    pass


class Pe64:
    def __init__(self, data: bytes):
        if data[:2] != b"MZ":
            raise PeError("not an MZ image")
        e_lfanew = _u32(data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise PeError("not a PE image")
        coff = e_lfanew + 4
        self.machine = _u16(data, coff)
        nsections = _u16(data, coff + 2)
        opt_size = _u16(data, coff + 16)
        opt = coff + 20
        magic = _u16(data, opt)
        if magic != 0x20B:
            raise PeError(f"not PE32+ (magic={magic:#x})")
        self.major_os = _u16(data, opt + 40)
        self.minor_os = _u16(data, opt + 42)
        self.major_subsys = _u16(data, opt + 48)
        self.minor_subsys = _u16(data, opt + 50)
        self.subsystem = _u16(data, opt + 68)
        num_rva_sizes = _u32(data, opt + 108)
        dirs = opt + 112
        import_rva = import_size = 0
        if num_rva_sizes > 1:
            import_rva = _u32(data, dirs + 8)
            import_size = _u32(data, dirs + 12)
        sections_off = opt + opt_size
        self.sections = []
        for i in range(nsections):
            s = sections_off + i * 40
            va = _u32(data, s + 12)
            raw_size = _u32(data, s + 16)
            raw_off = _u32(data, s + 20)
            vsize = _u32(data, s + 8)
            self.sections.append((va, max(vsize, raw_size), raw_off, raw_size))
        self.data = data
        self.import_rva = import_rva
        self.import_size = import_size

    def rva_to_off(self, rva: int) -> int | None:
        for va, vsize, raw_off, raw_size in self.sections:
            if va <= rva < va + max(vsize, 1):
                delta = rva - va
                if delta < raw_size:
                    return raw_off + delta
        return None

    def imports(self) -> list[tuple[str, list[str]]]:
        if not self.import_rva:
            return []
        off = self.rva_to_off(self.import_rva)
        if off is None:
            return []
        result = []
        while True:
            lookup_rva = _u32(self.data, off)
            name_rva = _u32(self.data, off + 12)
            first_thunk = _u32(self.data, off + 16)
            if lookup_rva == 0 and name_rva == 0 and first_thunk == 0:
                break
            name_off = self.rva_to_off(name_rva)
            dll = _read_cstr(self.data, name_off) if name_off is not None else "?"
            thunk_rva = lookup_rva or first_thunk
            names = []
            thunk_off = self.rva_to_off(thunk_rva) if thunk_rva else None
            if thunk_off is not None:
                t = thunk_off
                while True:
                    entry = _u64(self.data, t)
                    if entry == 0:
                        break
                    if (entry & (1 << 63)) == 0:
                        hint_rva = entry & 0x7FFFFFFF
                        n_off = self.rva_to_off(hint_rva)
                        if n_off is not None:
                            names.append(_read_cstr(self.data, n_off + 2))
                    t += 8
            result.append((dll, names))
            off += 20
        return result


def audit_file(path: pathlib.Path) -> list[str]:
    data = path.read_bytes()
    pe = Pe64(data)
    errors: list[str] = []
    if pe.machine != 0x8664:
        errors.append(f"{path.name}: machine {pe.machine:#x} is not AMD64")
    ver = (pe.major_subsys, pe.minor_subsys)
    if ver[0] > 6 or (ver[0] == 6 and ver[1] >= 2):
        errors.append(
            f"{path.name}: subsystem {pe.major_subsys}.{pe.minor_subsys} requires Windows 8+"
        )
    print(
        f"{path}: PE32+ AMD64 subsystem {pe.major_subsys}.{pe.minor_subsys} "
        f"os {pe.major_os}.{pe.minor_os}"
    )
    for dll, names in pe.imports():
        dll_l = dll.lower()
        print(f"  {dll}: {len(names)} imports")
        if dll_l in FORBIDDEN_DLLS:
            errors.append(f"{path.name}: dynamic CRT dependency {dll}")
        if dll_l.startswith("api-ms-win-crt-"):
            errors.append(f"{path.name}: Universal CRT forwarder {dll} (missing on stock Win7)")
        for n in names:
            if n in FORBIDDEN_IMPORT_NAMES:
                errors.append(f"{path.name}: imports {n} from {dll} (Windows 8+)")
    return errors


def collect_binaries(root: pathlib.Path) -> list[pathlib.Path]:
    found: list[pathlib.Path] = []
    if root.is_file():
        return [root]
    for pat in ("*.dll", "*.vst3", "*.exe"):
        found.extend(root.rglob(pat))
    binaries = []
    for p in found:
        if not p.is_file() or p.stat().st_size < 4096:
            continue
        if p.read_bytes()[:2] == b"MZ":
            binaries.append(p)
    return binaries


def _minimal_pe32plus(major_subsys: int, minor_subsys: int) -> bytes:
    """Build a tiny PE32+ image for auditor self-tests (not a runnable plugin)."""
    data = bytearray(1024)
    data[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    coff = e_lfanew + 4
    struct.pack_into("<H", data, coff, 0x8664)
    struct.pack_into("<H", data, coff + 2, 0)  # no sections; import dir unused
    struct.pack_into("<H", data, coff + 16, 240)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<H", data, opt + 40, 6)
    struct.pack_into("<H", data, opt + 42, 1)
    struct.pack_into("<H", data, opt + 48, major_subsys)
    struct.pack_into("<H", data, opt + 50, minor_subsys)
    struct.pack_into("<I", data, opt + 108, 16)
    return bytes(data)


def _self_test() -> None:
    import tempfile

    ok = _minimal_pe32plus(6, 1)
    bad_sub = _minimal_pe32plus(6, 2)
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        win7 = root / "ok.dll"
        win8 = root / "win8.dll"
        win7.write_bytes(ok)
        win8.write_bytes(bad_sub)
        err_ok = audit_file(win7)
        err_bad = audit_file(win8)
    if err_ok:
        raise SystemExit(f"self-test FAIL: Win7 stub rejected: {err_ok}")
    if not any("Windows 8+" in e for e in err_bad):
        raise SystemExit(f"self-test FAIL: Win8 subsystem not flagged: {err_bad}")
    print("OK pe_win7_audit self-test")


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "--self-test":
        _self_test()
        return
    if len(sys.argv) < 2:
        raise SystemExit("usage: pe_win7_audit.py <file-or-dir> [...]")
    errors: list[str] = []
    scanned = 0
    for arg in sys.argv[1:]:
        for path in collect_binaries(pathlib.Path(arg)):
            scanned += 1
            try:
                errors.extend(audit_file(path))
            except PeError as exc:
                errors.append(f"{path}: {exc}")
    if scanned == 0:
        raise SystemExit("FAIL: no PE binaries found")
    if errors:
        print("FAIL:")
        for e in errors:
            print(" ", e)
        raise SystemExit(1)
    print(f"OK: {scanned} binaries look Windows 7 compatible")


if __name__ == "__main__":
    main()
