"""Apple Fat Macho constants."""

import collections
import enum

# References: https://opensource.apple.com/source/xnu/xnu-6153.61.1
# EXTERNAL_HEADERS/mach-o/fat.h and
# EXTERNAL_HEADERS/mach-o/loader.h
FatHeader = collections.namedtuple("fat_header", ("magic", "nfat_arch"))
FatArch = collections.namedtuple("fat_arch", ("cputype", "cpusubtype", "offset", "size", "align", "flags"))

CPU_SUBTYPE_MULTIPLE = 0xFFFFFFFF
CPU_SUBTYPE_MASK = 0xFF000000


class CPUSubTypeFlag(enum.Enum):
    """CPU SubType Flags."""

    NO_FEATURES = 0x00000000
    LIB64 = 0x80000000


class Magic(enum.Enum):
    """File type magic byte patterns."""

    FAT_MAGIC = b"\xca\xfe\xba\xbe"
    FAT_CIGAM = b"\xbe\xba\xfe\xca"
    MH_MAGIC = b"\xfe\xed\xfa\xce"
    MH_CIGAM = b"\xce\xfa\xed\xfe"
    MH_MAGIC_64 = b"\xfe\xed\xfa\xcf"
    MH_CIGAM_64 = b"\xcf\xfa\xed\xfe"


# osfmk/mach/machine.h
class CPUArch(enum.IntEnum):
    """CPU Architectures."""

    ABI64 = 0x01000000
    ABI64_32 = 0x02000000


class CPUType(enum.IntEnum):
    """Supported CPU Type."""

    ANY = -1
    VAX = 1
    MC680x0 = 6
    X86 = 7
    I386 = X86
    X86_64 = X86 | CPUArch.ABI64
    MIPS = 8
    MC98000 = 10
    HPPA = 11
    ARM = 12
    ARM64 = ARM | CPUArch.ABI64
    ARM64_32 = ARM | CPUArch.ABI64_32
    MC88000 = 13
    SPARC = 14
    I860 = 15
    POWERPC = 18
    POWERPC64 = POWERPC | CPUArch.ABI64


class CPUSubTypeVAX(enum.IntEnum):
    """Supported VAX CPU Subtypes."""

    VAX_ALL = 0
    VAX780 = 1
    VAX785 = 2
    VAX750 = 3
    VAX730 = 4
    UVAXI = 5
    UVAXII = 6
    VAX8200 = 7
    VAX8500 = 8
    VAX8600 = 9
    VAX8650 = 10
    VAX8800 = 11
    UVAXIII = 12


class CPUSubTypeMC680x0(enum.IntEnum):
    """Supported MC680x0 CPU Subtypes."""

    MC680x0_ALL = 1
    MC68030 = 1
    MC68040 = 2
    MC68030_ONLY = 3


class CPUSubTypeX86(enum.IntEnum):
    """Supported x86 CPU Subtypes."""

    I386_ALL = 3 + (0 << 4)
    I386 = 3 + (0 << 4)
    I486 = 4 + (0 << 4)
    I486SX = 4 + (8 << 4)
    I586 = 5 + (0 << 4)
    PENT = 5 + (0 << 4)
    PENTPRO = 6 + (1 << 4)
    PENTII_M3 = 6 + (3 << 4)
    PENTII_M5 = 6 + (5 << 4)
    CELERON = 7 + (6 << 4)
    CELERON_MOBILE = 7 + (7 << 4)
    PENTIUM_3 = 8 + (0 << 4)
    PENTIUM_3_M = 8 + (1 << 4)
    PENTIUM_3_XEON = 8 + (2 << 4)
    PENTIUM_M = 9 + (0 << 4)
    PENTIUM_4 = 10 + (0 << 4)
    PENTIUM_4_M = 10 + (1 << 4)
    ITANIUM = 11 + (0 << 4)
    ITANIUM_2 = 11 + (1 << 4)
    XEON = 12 + (0 << 4)
    XEON_MP = 12 + (1 << 4)


class CPUSubTypeX8664(enum.IntEnum):
    """Supported x86/x64 CPU Subtypes."""

    X86_64_ALL = 3
    X64_64_H = 8


class CPUSubTypeMIPS(enum.IntEnum):
    """Supported MIPS CPU Subtypes."""

    MIPS_ALL = 0
    MIPS_R2300 = 1
    MIPS_R2600 = 2
    MIPS_R2800 = 3
    MIPS_R2000a = 4
    MIPS_R2000 = 5
    MIPS_R3000a = 6
    MIPS_R3000 = 7


class CPUSubTypeMC98000(enum.IntEnum):
    """Supported MC98000 CPU Subtypes."""

    MC98000_ALL = 0
    MC98601 = 1


class CPUSubTypeHPPA(enum.IntEnum):
    """Supported HPPA CPU Subtypes."""

    HPPA_ALL = 0
    HPPA_7100 = 0
    HPPA_7100LC = 1


class CPUSubTypeMC88000(enum.IntEnum):
    """Supported MC88000 CPU Subtypes."""

    MC88000_ALL = 0
    MC88100 = 1
    MC88110 = 2


class CPUSubTypeSPARC(enum.IntEnum):
    """Supported SPARC CPU Subtypes."""

    SPARC_ALL = 0


class CPUSubTypeI860(enum.IntEnum):
    """Supported I860 CPU Subtypes."""

    I860_ALL = 0
    I860_860 = 1


class CPUSubTypePowerPC(enum.IntEnum):
    """Supported PowerPC CPU Subtypes."""

    POWERPC_ALL = 0
    POWERPC_601 = 1
    POWERPC_602 = 2
    POWERPC_603 = 3
    POWERPC_603e = 4
    POWERPC_603ev = 5
    POWERPC_604 = 6
    POWERPC_604e = 7
    POWERPC_620 = 8
    POWERPC_750 = 9
    POWERPC_7400 = 10
    POWERPC_7450 = 11
    POWERPC_970 = 100


class CPUSubTypeARM(enum.IntEnum):
    """Supported ARM CPU Subtypes."""

    ARM_ALL = 0
    ARM_V4T = 5
    ARM_V6 = 6
    ARM_V5TEJ = 7
    ARM_XSCALE = 8
    ARM_V7 = 9
    ARM_V7F = 10
    ARM_V7S = 11
    ARM_V7K = 12
    ARM_V6M = 14
    ARM_V7M = 15
    ARM_V7EM = 16
    ARM_V8 = 13


class CPUSubTypeARM64(enum.IntEnum):
    """Supported ARM 64bit CPU Subtypes."""

    ARM64_ALL = 0
    ARM64_V8 = 1


CPUSubType = {
    CPUType.VAX: CPUSubTypeVAX,
    CPUType.MC680x0: CPUSubTypeMC680x0,
    CPUType.X86: CPUSubTypeX86,
    CPUType.X86_64: CPUSubTypeX8664,
    CPUType.MIPS: CPUSubTypeMIPS,
    CPUType.MC98000: CPUSubTypeMC98000,
    CPUType.HPPA: CPUSubTypeHPPA,
    CPUType.ARM: CPUSubTypeARM,
    CPUType.ARM64: CPUSubTypeARM64,
    CPUType.MC88000: CPUSubTypeMC88000,
    CPUType.SPARC: CPUSubTypeSPARC,
    CPUType.I860: CPUSubTypeI860,
    CPUType.POWERPC: CPUSubTypePowerPC,
    CPUType.POWERPC64: CPUSubTypePowerPC,
}
