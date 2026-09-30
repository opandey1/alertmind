"""Bounded, pure ELF64/amd64 loader-metadata candidate reader, never a loader.

Only program headers and selected dynamic strings are interpreted. This is not
full ELF validation, symbol/code analysis, dependency resolution or admission.
No section headers, relocations, constructors, libraries or binaries execute.
"""
import re
import struct

from .verify_pid1_ubuntu_archive import require

MAX_IMAGE = 32 * 1024 * 1024
MAX_PH = 256
MAX_DYNAMIC = 4096
MAX_STRTAB = 2 * 1024 * 1024
MAX_STRING = 4096
_NAME = re.compile(rb'[A-Za-z0-9][A-Za-z0-9._+-]{0,254}')
_PATH = re.compile(rb'/[A-Za-z0-9/._+-]{1,4095}')
_SEARCH = re.compile(rb'[A-Za-z0-9/._:+${}-]{1,4096}')


def _span(raw, offset, length):
    require(0 <= offset <= len(raw) and 0 <= length <= len(raw) - offset,
            'ELF_BOUNDS')
    return raw[offset:offset + length]


def _mapped_offset(loads, address, length):
    matches = [p[2] + address - p[3] for p in loads
               if p[3] <= address and address - p[3] <= p[5] and
               length <= p[5] - (address - p[3])]
    require(len(matches) == 1, 'ELF_MAPPING')
    return matches[0]


def _text(table, offset, pattern):
    require(0 <= offset < len(table), 'ELF_STRING')
    end = table.find(b'\0', offset, min(len(table), offset + MAX_STRING + 1))
    require(end > offset, 'ELF_STRING')
    value = table[offset:end]
    require(pattern.fullmatch(value) is not None, 'ELF_STRING')
    return value.decode('ascii')


def inspect_elf64(raw):
    """Return selected static metadata of supplied bytes; no authenticity claim."""
    require(type(raw) is bytes and 64 <= len(raw) <= MAX_IMAGE, 'ELF_SIZE')
    ident, kind, machine, version, _, phoff, _, _, ehsize, phsize, count, _, _, _ = \
        struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    require(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7] in (0, 3) and
            ident[8:] == b'\0' * 8 and kind in (2, 3) and machine == 62 and
            version == 1 and ehsize == 64 and phsize == 56 and
            1 <= count <= MAX_PH and phoff >= 64, 'ELF_HEADER')
    _span(raw, phoff, count * phsize)
    headers = tuple(struct.unpack_from('<IIQQQQQQ', raw, phoff + i * phsize)
                    for i in range(count))
    for p in headers:
        _span(raw, p[2], p[5])
        require(p[5] <= p[6] and p[3] + p[6] < 1 << 64 and
                (p[7] in (0, 1) or p[7] & (p[7] - 1) == 0), 'ELF_SEGMENT')
    loads = tuple(p for p in headers if p[0] == 1)
    dynamic = tuple(p for p in headers if p[0] == 2)
    interp = tuple(p for p in headers if p[0] == 3)
    require(loads and len(dynamic) == 1 and len(interp) <= 1, 'ELF_SEGMENTS')
    p = dynamic[0]
    require(0 < p[5] <= MAX_DYNAMIC * 16 and p[5] % 16 == 0, 'ELF_DYNAMIC')
    require(_mapped_offset(loads, p[3], p[5]) == p[2], 'ELF_MAPPING')
    pairs = []
    ended = False
    for offset in range(p[2], p[2] + p[5], 16):
        tag, value = struct.unpack_from('<qQ', raw, offset)
        if tag == 0:
            # The ABI ends the array at DT_NULL; its value and bytes after
            # that terminator are not dynamic entries. Real core-library
            # padding is not always zero. Do not invent a padding contract.
            ended = True
            break
        pairs.append((tag, value))
    require(ended, 'ELF_DYNAMIC')

    def one(tag, required=False):
        values = [v for t, v in pairs if t == tag]
        require(len(values) == 1 if required else len(values) <= 1, 'ELF_TAG')
        return values[0] if values else None

    address, size = one(5, True), one(10, True)
    require(0 < size <= MAX_STRTAB, 'ELF_STRTAB')
    table = _span(raw, _mapped_offset(loads, address, size), size)
    require(table[0] == 0, 'ELF_STRTAB')
    needed = tuple(_text(table, v, _NAME) for t, v in pairs if t == 1)
    require(len(needed) <= 64 and len(set(needed)) == len(needed), 'ELF_NEEDED')
    soname, rpath, runpath = one(14), one(15), one(29)
    interpreter = None
    if interp:
        p = interp[0]
        require(1 < p[5] <= MAX_STRING, 'ELF_INTERPRETER')
        text = _span(raw, p[2], p[5])
        require(text.endswith(b'\0') and b'\0' not in text[:-1] and
                _PATH.fullmatch(text[:-1]) is not None, 'ELF_INTERPRETER')
        interpreter = text[:-1].decode('ascii')
    return {'elf_type': 'ET_DYN' if kind == 3 else 'ET_EXEC',
            'interpreter': interpreter, 'needed': list(needed),
            'soname': None if soname is None else _text(table, soname, _NAME),
            'rpath': None if rpath is None else _text(table, rpath, _SEARCH),
            'runpath': None if runpath is None else _text(table, runpath, _SEARCH)}
