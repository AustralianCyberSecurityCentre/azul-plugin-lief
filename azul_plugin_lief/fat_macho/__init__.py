"""Fat MachO unpacking package."""

from .const import (  # noqa: F401
    CPUArch,
    CPUSubType,
    CPUSubTypeFlag,
    CPUType,
    FatArch,
    FatHeader,
    Magic,
)
from .unpack import BadMagicError, unpack  # noqa: F401
