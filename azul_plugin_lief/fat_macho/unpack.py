"""Unpacking routine for Apple Fat MachO format."""

import struct

from .const import (
    CPU_SUBTYPE_MASK,
    CPUSubType,
    CPUSubTypeFlag,
    CPUType,
    FatArch,
    FatHeader,
    Magic,
)


class BadMagicError(ValueError):
    """Invalid/unknown file magic exception."""


def unpack(data):
    """Parse fat macho byte str, returning a tuple of header and archs list."""
    if len(data) < 8:
        raise IndexError("Need at least 8 bytes to unpack fat_header")

    endianness = magic = None
    try:
        magic = Magic(data[0:4])
    except ValueError:
        # magic not known Magic value
        pass
    else:
        if magic == Magic.FAT_MAGIC:
            # Big endian
            endianness = ">"
        elif magic == Magic.FAT_CIGAM:
            # Little endian
            endianness = "<"

    if magic is None or endianness is None:
        raise BadMagicError("Unknown magic, likely not fat Mach-O")

    nfat_arch = struct.unpack("{}I".format(endianness), data[4:8])[0]
    header = FatHeader(magic, nfat_arch)
    if len(data) < 8 + nfat_arch * 20:
        raise IndexError("Not enough data provided to unpack {} fat_arch's".format(nfat_arch))

    # treat cpu type/subtype as unsigned for simpler flag checking
    fat_arch_s = "{}IIIII".format(endianness)
    fat_arch_size = struct.calcsize(fat_arch_s)
    archs = []
    for off in range(8, 8 + nfat_arch * fat_arch_size, fat_arch_size):
        cputype, cpusubtype, offset, size, align = struct.unpack(fat_arch_s, data[off : off + fat_arch_size])
        cputype = CPUType(cputype)
        capflags = cpusubtype & CPU_SUBTYPE_MASK
        cpusubtype ^= capflags
        capflags = CPUSubTypeFlag(capflags)
        cpusubtype = CPUSubType[cputype](cpusubtype)
        archs.append(FatArch(cputype, cpusubtype, offset, size, align, capflags))

    return header, archs
