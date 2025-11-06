import unittest

from azul_plugin_lief.fat_macho import (
    BadMagicError,
    CPUSubType,
    CPUSubTypeFlag,
    CPUType,
    FatArch,
    FatHeader,
    Magic,
    unpack,
)


class TestFatMachOUnpack(unittest.TestCase):
    def test_fat_macho(self):
        hdr = unpack(FAT_MACHO_HEADER)
        self.assertEqual(hdr, FAT_MACHO_HEADER_RESULT)

    def test_fat_macho_le(self):
        hdr = unpack(FAT_MACHO_HEADER_LE)
        self.assertEqual(hdr, FAT_MACHO_HEADER_LE_RESULT)

    def test_fat_macho_subtype_capability(self):
        hdr = unpack(FAT_MACHO_HEADER_64BIT_LIB_SUBTYPE)
        self.assertEqual(hdr, FAT_MACHO_HEADER_64BIT_LIB_SUBTYPE_RESULT)

    def test_fit_macho(self):
        self.assertRaises(BadMagicError, unpack, MACHO_HEADER)

    def test_not_enough_data(self):
        self.assertRaises(IndexError, unpack, b"\xca\xfe\xba\xbe")
        self.assertRaises(IndexError, unpack, FAT_MACHO_HEADER[:16])

    def test_bad_magic(self):
        self.assertRaises(BadMagicError, unpack, b"\0" * 64)

    def test_bad_arch(self):
        self.assertRaises(ValueError, unpack, FAT_MACHO_HEADER_BAD_ARCH)


FAT_MACHO_HEADER = b"""\
\xca\xfe\xba\xbe\x00\x00\x00\x03\x00\x00\x00\x0c\x00\x00\x00\x09\
\x00\x00\x40\x00\x01\x68\x48\x10\x00\x00\x00\x0e\x00\x00\x00\x0c\
\x00\x00\x00\x0b\x01\x68\xc0\x00\x01\x68\x48\x00\x00\x00\x00\x0e\
\x01\x00\x00\x0c\x00\x00\x00\x00\x02\xd1\x40\x00\x01\xa5\x11\xd0\
\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
"""
FAT_MACHO_HEADER_RESULT = (
    FatHeader(magic=Magic.FAT_MAGIC, nfat_arch=3),
    [
        FatArch(
            cputype=CPUType.ARM,
            cpusubtype=CPUSubType[CPUType.ARM].ARM_V7,
            offset=16384,
            size=23611408,
            align=14,
            flags=CPUSubTypeFlag.NO_FEATURES,
        ),
        FatArch(
            cputype=CPUType.ARM,
            cpusubtype=CPUSubType[CPUType.ARM].ARM_V7S,
            offset=23642112,
            size=23611392,
            align=14,
            flags=CPUSubTypeFlag.NO_FEATURES,
        ),
        FatArch(
            cputype=CPUType.ARM64,
            cpusubtype=CPUSubType[CPUType.ARM64].ARM64_ALL,
            offset=47267840,
            size=27595216,
            align=14,
            flags=CPUSubTypeFlag.NO_FEATURES,
        ),
    ],
)

FAT_MACHO_HEADER_LE = b"""\
\xbe\xba\xfe\xca\x03\x00\x00\x00\x0c\x00\x00\x00\x09\x00\x00\x00\
\x00\x40\x00\x00\x10\x48\x68\x01\x0e\x00\x00\x00\x0c\x00\x00\x00\
\x0b\x00\x00\x00\x00\xc0\x68\x01\x00\x48\x68\x01\x0e\x00\x00\x00\
\x0c\x00\x00\x01\x00\x00\x00\x00\x00\x40\xd1\x02\xd0\x11\xa5\x01\
\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
"""
FAT_MACHO_HEADER_LE_RESULT = (
    FatHeader(magic=Magic.FAT_CIGAM, nfat_arch=3),
    [
        FatArch(
            cputype=CPUType.ARM,
            cpusubtype=CPUSubType[CPUType.ARM].ARM_V7,
            offset=16384,
            size=23611408,
            align=14,
            flags=CPUSubTypeFlag.NO_FEATURES,
        ),
        FatArch(
            cputype=CPUType.ARM,
            cpusubtype=CPUSubType[CPUType.ARM].ARM_V7S,
            offset=23642112,
            size=23611392,
            align=14,
            flags=CPUSubTypeFlag.NO_FEATURES,
        ),
        FatArch(
            cputype=CPUType.ARM64,
            cpusubtype=CPUSubType[CPUType.ARM64].ARM64_ALL,
            offset=47267840,
            size=27595216,
            align=14,
            flags=CPUSubTypeFlag.NO_FEATURES,
        ),
    ],
)

MACHO_HEADER = """\
\xce\xfa\xed\xfe\x0c\x00\x00\x00\x09\x00\x00\x00\x02\x00\x00\x00\
\x40\x00\x00\x00\x18\x1a\x00\x00\x85\x80\x21\x00\x01\x00\x00\x00
"""

FAT_MACHO_HEADER_BAD_ARCH = b"""\
\xca\xfe\xba\xbe\x00\x00\x00\x03\x00\x00\x00\x0c\x00\x00\x00\x09\
\x00\x00\x40\x00\x01\x68\x48\x10\x00\x00\x00\x0e\x00\x00\x00\x0c\
\x00\x00\x00\x0b\x01\x68\xc0\x00\x01\x68\x48\x00\x00\x00\x00\x0e\
\x01\x00\x00\x0c\xff\xff\xff\xff\x02\xd1\x40\x00\x01\xa5\x11\xd0\
\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
"""

FAT_MACHO_HEADER_64BIT_LIB_SUBTYPE = b"""\
\xca\xfe\xba\xbe\x00\x00\x00\x02\x01\x00\x00\x07\x80\x00\x00\x03\
\x00\x00\x10\x00\x00\x00\xff\x10\x00\x00\x00\x0c\x00\x00\x00\x07\
\x00\x00\x00\x03\x00\x01\x10\x00\x00\x00\xe5\x90\x00\x00\x00\x0c\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
"""
FAT_MACHO_HEADER_64BIT_LIB_SUBTYPE_RESULT = (
    FatHeader(magic=Magic.FAT_MAGIC, nfat_arch=2),
    [
        FatArch(
            cputype=CPUType.X86_64,
            cpusubtype=CPUSubType[CPUType.X86_64].X86_64_ALL,
            offset=4096,
            size=65296,
            align=12,
            flags=CPUSubTypeFlag.LIB64,
        ),
        FatArch(
            cputype=CPUType.X86,
            cpusubtype=CPUSubType[CPUType.X86].I386_ALL,
            offset=69632,
            size=58768,
            align=12,
            flags=CPUSubTypeFlag.NO_FEATURES,
        ),
    ],
)
