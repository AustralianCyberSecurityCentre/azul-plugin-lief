"""Parse Mach-O file type with LIEF.

This plugin uses the library to instrument executable formats (LIEF) to extract
information from Mach-O files. Information extracted includes:
 - header data
 - sections
 - imports and exports
 - load command metadata
"""

from hashlib import md5
from uuid import UUID

import lief
from azul_runner import (
    FV,
    BinaryPlugin,
    DataLabel,
    Feature,
    FeatureType,
    Filepath,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from lief import MachO

from .fat_macho import const

BIG_INT_MAX = (1 << 63) - 1


def enum_wrapper(macho_enum):
    """Wrap a macho enum to allow getting the name of the enum rather than the Enum itself."""

    def get_enum_name_or_none(value: int, default=None) -> str | None:
        """Get the name of an enum or the default value if that fails."""
        try:
            return macho_enum.from_value(value).__name__
        except Exception:
            return default

    return get_enum_name_or_none


CPU_TYPES = enum_wrapper(MachO.Header.CPU_TYPE)
FILE_TYPES = enum_wrapper(MachO.Header.FILE_TYPE)
LOAD_COMMAND_TYPES = enum_wrapper(MachO.LoadCommand.TYPE)


# lief doesn't map subtypes, so reuse consts in fat_macho project
def get_cpu_subtype(cpu_type, subtype):
    """Get the human readable CPU subtype from the field."""
    try:
        flags = subtype & const.CPU_SUBTYPE_MASK
        s = subtype ^ flags
        return const.CPUSubType[int(cpu_type)](s).name
    except (KeyError, TypeError):
        return str(subtype)


class AzulPluginLiefMachO(BinaryPlugin):
    """Parse Mach-O file type with LIEF."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.04.08"
    SETTINGS = add_settings(filter_data_types={DataLabel.CONTENT: ["executable/mach-o"]})
    # Ensure any changes are kept in sync with features set by virustotal filemapper
    FEATURES = [
        # Common/generic features
        Feature(name="tag", desc="Any informational label about the binary", type=FeatureType.String),
        # Header features
        Feature(name="macho_magic", desc="Magic value of Mach-O indicating endianess", type=FeatureType.String),
        Feature(name="macho_cpu_type", desc="CPU type of Mach-O", type=FeatureType.String),
        Feature(name="macho_cpu_subtype", desc="CPU subtype of Mach-O", type=FeatureType.String),
        Feature(name="macho_file_type", desc="File type of Mach-O", type=FeatureType.String),
        Feature(name="macho_header_flag", desc="Flags set in Mach-O header", type=FeatureType.String),
        Feature(name="macho_commands_count", desc="Number of load commands in Mach-O", type=FeatureType.Integer),
        Feature(name="macho_commands_size", desc="Size of all load commands in Mach-O", type=FeatureType.Integer),
        Feature(
            name="macho_header_reserved", desc="Reserved field in Mach-O, should be zero", type=FeatureType.Integer
        ),
        # Generic load command features
        Feature(name="macho_load_command", desc="Type of load command in binary", type=FeatureType.String),
        Feature(name="macho_load_command_count", desc="Number of commands with given type", type=FeatureType.Integer),
        Feature(name="macho_load_command_offset", desc="Offset into load command table", type=FeatureType.Integer),
        Feature(name="macho_load_command_type", desc="Load command type for offset", type=FeatureType.String),
        Feature(name="macho_load_command_size", desc="Size of load command data", type=FeatureType.Integer),
        Feature(name="macho_load_command_hash", desc="MD5 hash of load command data", type=FeatureType.String),
        # Segment command features
        Feature(name="macho_segment_name", desc="Name of segment in Mach-O file", type=FeatureType.String),
        Feature(name="macho_segment_virtual_address", desc="Virtual address of segment", type=FeatureType.Integer),
        Feature(name="macho_segment_virtual_size", desc="Virtual size of segment", type=FeatureType.Integer),
        Feature(name="macho_segment_raw_offset", desc="Offset of data in file for segment", type=FeatureType.Integer),
        Feature(name="macho_segment_raw_size", desc="Size of data in file for segment", type=FeatureType.Integer),
        Feature(name="macho_segment_max_protection", desc="Maximum protection for segment", type=FeatureType.String),
        Feature(name="macho_segment_init_protection", desc="Initial protection for segment", type=FeatureType.String),
        Feature(name="macho_segment_flags", desc="Flags of segment", type=FeatureType.String),
        Feature(name="macho_segment_sections_count", desc="Number of sections in segment", type=FeatureType.Integer),
        Feature(
            name="macho_segment_relocations_count", desc="Number of relocations in segment", type=FeatureType.Integer
        ),
        Feature(name="macho_segment_hash", desc="MD5 of the segment data", type=FeatureType.String),
        # Section features (from segment commands)
        Feature(name="macho_section_name", desc="Name of the section in segment", type=FeatureType.String),
        Feature(
            name="macho_section_fullname", desc="Full name of the section including segment", type=FeatureType.String
        ),
        Feature(name="macho_section_size", desc="Size of the section", type=FeatureType.Integer),
        Feature(name="macho_section_offset", desc="Offset of data in file for section", type=FeatureType.Integer),
        Feature(name="macho_section_virtual_address", desc="Virtual address of section", type=FeatureType.Integer),
        Feature(name="macho_section_alignment", desc="Alignment of the section", type=FeatureType.Integer),
        Feature(
            name="macho_section_relocations_offset",
            desc="Relocation data offset in file for section",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_section_relocations_count", desc="Number of relocations for section", type=FeatureType.Integer
        ),
        Feature(name="macho_section_type", desc="Type of section", type=FeatureType.String),
        Feature(name="macho_section_reserved", desc="Reserved data in section", type=FeatureType.String),
        Feature(name="macho_section_flag", desc="Flags of section", type=FeatureType.String),
        Feature(name="macho_section_hash", desc="MD5 hash of data in section", type=FeatureType.String),
        # Dylib command features
        Feature(name="macho_dylib_name", desc="Name of dylib", type=Filepath),
        Feature(name="macho_dylib_timestamp", desc="Name of dylib", type=FeatureType.Integer),
        Feature(name="macho_dylib_current_version", desc="Current version of dylib", type=FeatureType.String),
        Feature(name="macho_dylib_compat_version", desc="Compatibility version of dylib", type=FeatureType.String),
        # RPath command feature
        Feature(name="macho_rpath", desc="Run path used to find @rpath prefixed dylibs", type=FeatureType.String),
        # UUID command feature
        Feature(name="macho_uuid", desc="UUID added by the linker to the Mach-O", type=FeatureType.String),
        # Dynamic linker command feature
        Feature(
            name="macho_dynamic_linker_name",
            desc="Name of dynamic linker (for self-identification)",
            type=FeatureType.String,
        ),
        # Thread command features
        Feature(
            name="macho_thread_state_hash", desc="MD5 hash of the thread state structure", type=FeatureType.String
        ),
        Feature(name="macho_thread_flavor", desc="Flavour of thread state", type=FeatureType.Integer),
        Feature(name="macho_thread_count", desc="Count of longs in thread state", type=FeatureType.Integer),
        Feature(name="macho_thread_pc", desc="Initial PC value of thread", type=FeatureType.Integer),
        # Symbol command features
        Feature(name="macho_symbol_table_offset", desc="Offset in file to symbol table", type=FeatureType.Integer),
        Feature(
            name="macho_symbol_table_symbols_count",
            desc="Number of symbols in the symbol table",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_symbol_table_strings_offset",
            desc="Offset in file to the strings table",
            type=FeatureType.Integer,
        ),
        Feature(name="macho_symbol_table_strings_size", desc="Size of the strings table", type=FeatureType.Integer),
        # Dynamic symbol command features
        Feature(
            name="macho_dynamic_symbol_local_index",
            desc="Index of first symbol in group of local symbols",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_local_count",
            desc="Number of symbols in group of local symbols",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_external_defined_index",
            desc="Index to group of defined external symbols",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_external_defined_count",
            desc="Count of symbols in defined external group",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_undefined_index",
            desc="First symbol index in group of undefined external symbols",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_undefined_count",
            desc="Count of symbols in the undefined external group",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_toc_offset",
            desc="Byte offset from start of file to the table of contents, should be zero",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_toc_count",
            desc="Number of entries in the table of contents, should be zero",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_module_table_offset",
            desc="Byte offset from start of file to the module table data, should be zero",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_module_table_count",
            desc="Number of entries in the module table, should be zero",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_external_reference_offset",
            desc="Byte offset from start of file to the external reference table data, should be zero",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_external_reference_count",
            desc="Number of entries in the external references table, should be zero",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_indirect_symbol_offset",
            desc="Byte offset from start of file to the indirect symbol table data",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_indirect_symbol_count",
            desc="Number of entries in the indirect symbol table",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_external_relocation_offset",
            desc="Byte offset from start of file to the external relocation table data, should be zero",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_external_relocation_count",
            desc="Number of entries in the external relocation table, should be zero",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_local_relocation_offset",
            desc="Byte offset from start of file to the local relocation table data, should be zero",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dynamic_symbol_local_relocation_count",
            desc="Number of entries in the local relocation table, should be zero",
            type=FeatureType.Integer,
        ),
        # Dyld info command features
        Feature(
            name="macho_dyld_info_rebase_offset",
            desc="Offset in file of the rebase information",
            type=FeatureType.Integer,
        ),
        Feature(name="macho_dyld_info_rebase_size", desc="Size of the rebase information", type=FeatureType.Integer),
        Feature(
            name="macho_dyld_info_rebase_opcodes_hash", desc="MD5 hash of the rebase opcodes", type=FeatureType.String
        ),
        Feature(
            name="macho_dyld_info_bind_offset", desc="Offset in file of the bind information", type=FeatureType.Integer
        ),
        Feature(name="macho_dyld_info_bind_size", desc="Size of the bind information", type=FeatureType.Integer),
        Feature(
            name="macho_dyld_info_bind_opcodes_hash", desc="MD5 hash of the bind opcodes", type=FeatureType.String
        ),
        Feature(
            name="macho_dyld_info_weak_bind_offset",
            desc="Offset in file of the weak bind information",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dyld_info_weak_bind_size", desc="Size of the weak bind information", type=FeatureType.Integer
        ),
        Feature(
            name="macho_dyld_info_weak_bind_opcodes_hash",
            desc="MD5 hash of the weak bind opcodes",
            type=FeatureType.String,
        ),
        Feature(
            name="macho_dyld_info_lazy_bind_offset",
            desc="Offset in file of the lazy bind information",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_dyld_info_lazy_bind_size", desc="Size of the lazy bind information", type=FeatureType.Integer
        ),
        Feature(
            name="macho_dyld_info_lazy_bind_opcodes_hash",
            desc="MD5 hash of the lazy bind opcodes",
            type=FeatureType.String,
        ),
        Feature(
            name="macho_dyld_info_export_offset",
            desc="Offset in the file of the export information",
            type=FeatureType.Integer,
        ),
        Feature(name="macho_dyld_info_export_size", desc="Size of the export information", type=FeatureType.Integer),
        Feature(name="macho_export_name", desc="Exported symbol name", type=FeatureType.String),
        Feature(name="macho_export_kind", desc="Kind of exported symbol", type=FeatureType.String),
        Feature(name="macho_export_flag", desc="Flags of the exported symbol", type=FeatureType.String),
        Feature(name="macho_export_address", desc="Address of the exported symbol", type=FeatureType.Integer),
        Feature(name="macho_export_alias_name", desc="Name of the alias exported", type=FeatureType.String),
        Feature(
            name="macho_export_alias_library_name", desc="Library name of the alias exported", type=FeatureType.String
        ),
        # Source version command feature
        Feature(
            name="macho_source_version", desc="Version of the source used to build the binary", type=FeatureType.String
        ),
        # Minimum targeted OS version command features
        Feature(
            name="macho_minimum_version", desc="Minimum targeted operating system version", type=FeatureType.String
        ),
        Feature(name="macho_minimum_sdk_version", desc="Minimum targeted SDK version", type=FeatureType.String),
        # Code signature features
        Feature(
            name="macho_code_signature_offset", desc="Offset in the binary to the signature", type=FeatureType.Integer
        ),
        Feature(name="macho_code_signature_size", desc="Size of the signature", type=FeatureType.Integer),
        # Data in code command features
        Feature(
            name="macho_data_in_code_offset",
            desc="Offset in the binary to the data in code table",
            type=FeatureType.Integer,
        ),
        Feature(name="macho_data_in_code_size", desc="Size of the data in code table", type=FeatureType.Integer),
        Feature(name="macho_data_in_code_type", desc="Types of data in code", type=FeatureType.String),
        Feature(name="macho_data_in_code_type_count", desc="Count of types of data in code", type=FeatureType.Integer),
        Feature(
            name="macho_data_in_code_type_max_length", desc="Maximum size of data in code", type=FeatureType.Integer
        ),
        # Main command features
        Feature(name="macho_main_entrypoint", desc="Program entry point", type=FeatureType.Integer),
        Feature(name="macho_main_stack_size", desc="Program stack size", type=FeatureType.Integer),
        # Function starts command features
        Feature(
            name="macho_function_starts_offset",
            desc="Offset in file to the function starts table",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_function_starts_size",
            desc="Size of the functions list in the binary",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_function_starts",
            desc="Number of function starts indicated in binary",
            type=FeatureType.Integer,
        ),
        # Segment split info command features
        Feature(
            name="macho_segment_split_info_offset",
            desc="Offset in file to segment split info",
            type=FeatureType.Integer,
        ),
        Feature(name="macho_segment_split_info_size", desc="Size of the segment split info", type=FeatureType.Integer),
        # Sub-framework command feature
        Feature(
            name="macho_subframework_umbrella_name", desc="Umbrella name of the sub-framework", type=FeatureType.String
        ),
        # Dyld environment command feature
        Feature(
            name="macho_dynamic_linker_environment", desc="Environment of the dynamic linker", type=FeatureType.String
        ),
        # Encryption info command features
        Feature(
            name="macho_encryption_info_offset",
            desc="Offset in file to the encryption information",
            type=FeatureType.Integer,
        ),
        Feature(
            name="macho_encryption_info_size", desc="Size of the encryption information", type=FeatureType.Integer
        ),
        Feature(
            name="macho_encryption_info_id",
            desc="Encryption system ID to use, 0 means not encrypted",
            type=FeatureType.Integer,
        ),
    ]

    def execute(self, job: Job):
        """Process any Mach-O file and attempt to parse using LIEF."""
        self.features = {}
        buf = job.get_data()
        macho_file = MachO.parse(buf.get_filepath(), config=MachO.ParserConfig.deep)
        if not macho_file or isinstance(macho_file, lief.lief_errors):
            # if a lief error occured.
            self.features["tag"] = "macho_invalid"
        else:
            # we get a MachO.FatBinary from parse()
            # for a proper fat Mach-O LIEF's support for FatBinaries is too
            # limited, so it is handled in the fat_macho plugin (which will
            # pass the binaries to lief)
            # for a slim Mach-O we extract the MachO.Binary object and go
            if isinstance(macho_file, MachO.FatBinary) and macho_file.size > 1:
                return State(State.Label.OPT_OUT, "macho_fat", "lief has limited support for fat macho files")

            if isinstance(macho_file, MachO.FatBinary) and macho_file.size == 1:
                macho_file = macho_file.at(0)
                if macho_file.fat_offset != 0:
                    return State(
                        State.Label.OPT_OUT, "macho_fat_offset", "lief has limited support for fat macho files"
                    )

            if isinstance(macho_file, MachO.Binary):
                self._handle_macho_header(macho_file)
                self._handle_macho_load_commands(macho_file)
        self.add_many_feature_values(self.features)

    def _handle_macho_header(self, macho_file: MachO.Binary):
        """Extract the Mach-O header."""
        header = macho_file.header

        self.features["macho_magic"] = header.magic.name
        self.features["macho_cpu_type"] = CPU_TYPES(header.cpu_type, str(int(header.cpu_type)))
        self.features["macho_cpu_subtype"] = get_cpu_subtype(header.cpu_type, header.cpu_subtype)
        self.features["macho_file_type"] = FILE_TYPES(header.file_type, str(int(header.file_type)))
        self.features["macho_header_flag"] = [f.name for f in header.flags_list]
        self.features["macho_commands_count"] = header.nb_cmds
        self.features["macho_commands_size"] = header.sizeof_cmds
        self.features["macho_header_reserved"] = header.reserved

    def _handle_macho_load_commands(self, macho_file: MachO.Binary):
        """Extract the Mach-O load commands.

        Each load command (segments, encryption, dylib, entry point, etc) is
        handled by different functions.
        """
        if not macho_file.commands:
            self.features.setdefault("tag", set()).add("macho_no_load_commands")
            return

        handlers = {
            "SEGMENT": self._handle_macho_lc_segment_command,
            "SEGMENT_64": self._handle_macho_lc_segment_command,
            "LOAD_WEAK_DYLIB": self._handle_macho_lc_dylib_command,
            "ID_DYLIB": self._handle_macho_lc_dylib_command,
            "LOAD_DYLIB": self._handle_macho_lc_dylib_command,
            "REEXPORT_DYLIB": self._handle_macho_lc_dylib_command,
            "LOAD_UPWARD_DYLIB": self._handle_macho_lc_dylib_command,
            "LAZY_LOAD_DYLIB": self._handle_macho_lc_dylib_command,
            "RPATH": self._handle_macho_lc_rpath_command,
            "UUID": self._handle_macho_lc_uuid_command,
            "LOAD_DYLINKER": self._handle_macho_lc_dylinker_command,
            "ID_DYLINKER": self._handle_macho_lc_dylinker_command,
            "THREAD": self._handle_macho_lc_thread_command,
            "UNIXTHREAD": self._handle_macho_lc_thread_command,
            "SYMTAB": self._handle_macho_lc_symtab_command,
            "DYSYMTAB": self._handle_macho_lc_dysymtab_command,
            "DYLD_INFO": self._handle_macho_lc_dyld_info_command,
            "DYLD_INFO_ONLY": self._handle_macho_lc_dyld_info_command,
            "SOURCE_VERSION": self._handle_macho_lc_source_version_command,
            "VERSION_MIN_MACOSX": self._handle_macho_lc_version_min_command,
            "VERSION_MIN_IPHONEOS": self._handle_macho_lc_version_min_command,
            "DYLIB_CODE_SIGN_DRS": self._handle_macho_lc_code_signature_command,
            "CODE_SIGNATURE": self._handle_macho_lc_code_signature_command,
            "DATA_IN_CODE": self._handle_macho_lc_data_in_code_command,
            "MAIN": self._handle_macho_lc_main_command,
            "FUNCTION_STARTS": self._handle_macho_lc_function_starts_command,
            "SEGMENT_SPLIT_INFO": self._handle_macho_lc_segment_split_info_command,
            "SUB_FRAMEWORK": self._handle_macho_lc_sub_framework_command,
            "DYLD_ENVIRONMENT": self._handle_macho_lc_dyld_environment_command,
            "ENCRYPTION_INFO": self._handle_macho_lc_encryption_info_command,
            "ENCRYPTION_INFO_64": self._handle_macho_lc_encryption_info_command,
        }

        self.features["macho_load_command_offset"] = []
        self.features["macho_load_command_type"] = []
        self.features["macho_load_command_size"] = []
        self.features["macho_load_command_hash"] = []

        self.features["macho_segment_name"] = []
        self.features["macho_segment_virtual_address"] = []
        self.features["macho_segment_virtual_size"] = []
        self.features["macho_segment_raw_size"] = []
        self.features["macho_segment_raw_offset"] = []
        self.features["macho_segment_max_protection"] = []
        self.features["macho_segment_init_protection"] = []
        self.features["macho_segment_flags"] = []
        self.features["macho_segment_sections_count"] = []
        self.features["macho_segment_relocations_count"] = []
        self.features["macho_segment_hash"] = []

        self.features["macho_section_name"] = []
        self.features["macho_section_fullname"] = []
        self.features["macho_section_size"] = []
        self.features["macho_section_offset"] = []
        self.features["macho_section_virtual_address"] = []
        self.features["macho_section_alignment"] = []
        self.features["macho_section_relocations_offset"] = []
        self.features["macho_section_relocations_count"] = []
        self.features["macho_section_type"] = []
        self.features["macho_section_reserved"] = []
        self.features["macho_section_flag"] = []
        self.features["macho_section_hash"] = []

        self.features["macho_dylib_name"] = []
        self.features["macho_dylib_timestamp"] = []
        self.features["macho_dylib_current_version"] = []
        self.features["macho_dylib_compat_version"] = []

        self.features["macho_rpath"] = []

        self.features["macho_uuid"] = []

        self.features["macho_dynamic_linker_name"] = []

        self.features["macho_thread_flavor"] = []
        self.features["macho_thread_count"] = []
        self.features["macho_thread_state_hash"] = []
        self.features["macho_thread_pc"] = []

        self.features["macho_symbol_table_offset"] = []
        self.features["macho_symbol_table_symbols_count"] = []
        self.features["macho_symbol_table_strings_offset"] = []
        self.features["macho_symbol_table_strings_size"] = []

        self.features["macho_dynamic_symbol_local_index"] = []
        self.features["macho_dynamic_symbol_local_count"] = []
        self.features["macho_dynamic_symbol_external_defined_index"] = []
        self.features["macho_dynamic_symbol_external_defined_count"] = []
        self.features["macho_dynamic_symbol_undefined_index"] = []
        self.features["macho_dynamic_symbol_undefined_count"] = []
        self.features["macho_dynamic_symbol_toc_offset"] = []
        self.features["macho_dynamic_symbol_toc_count"] = []
        self.features["macho_dynamic_symbol_module_table_offset"] = []
        self.features["macho_dynamic_symbol_module_table_count"] = []
        self.features["macho_dynamic_symbol_external_reference_offset"] = []
        self.features["macho_dynamic_symbol_external_reference_count"] = []
        self.features["macho_dynamic_symbol_indirect_symbol_offset"] = []
        self.features["macho_dynamic_symbol_indirect_symbol_count"] = []
        self.features["macho_dynamic_symbol_external_relocation_offset"] = []
        self.features["macho_dynamic_symbol_external_relocation_count"] = []
        self.features["macho_dynamic_symbol_local_relocation_offset"] = []
        self.features["macho_dynamic_symbol_local_relocation_count"] = []

        self.features["macho_dyld_info_rebase_offset"] = []
        self.features["macho_dyld_info_rebase_size"] = []
        self.features["macho_dyld_info_rebase_opcodes_hash"] = []
        self.features["macho_dyld_info_bind_offset"] = []
        self.features["macho_dyld_info_bind_size"] = []
        self.features["macho_dyld_info_bind_opcodes_hash"] = []
        self.features["macho_dyld_info_weak_bind_offset"] = []
        self.features["macho_dyld_info_weak_bind_size"] = []
        self.features["macho_dyld_info_weak_bind_opcodes_hash"] = []
        self.features["macho_dyld_info_lazy_bind_offset"] = []
        self.features["macho_dyld_info_lazy_bind_size"] = []
        self.features["macho_dyld_info_lazy_bind_opcodes_hash"] = []
        self.features["macho_dyld_info_export_offset"] = []
        self.features["macho_dyld_info_export_size"] = []

        self.features["macho_export_name"] = []
        self.features["macho_export_kind"] = []
        self.features["macho_export_flag"] = []
        self.features["macho_export_address"] = []
        self.features["macho_export_alias_name"] = []
        self.features["macho_export_alias_library_name"] = []

        self.features["macho_source_version"] = []

        self.features["macho_minimum_version"] = []
        self.features["macho_minimum_sdk_version"] = []

        self.features["macho_code_signature_offset"] = []
        self.features["macho_code_signature_size"] = []

        self.features["macho_data_in_code_offset"] = []
        self.features["macho_data_in_code_size"] = []
        self.features["macho_data_in_code_type"] = []
        self.features["macho_data_in_code_type_count"] = []
        self.features["macho_data_in_code_type_max_length"] = []

        self.features["macho_main_entrypoint"] = []
        self.features["macho_main_stack_size"] = []

        self.features["macho_function_starts_offset"] = []
        self.features["macho_function_starts_size"] = []
        self.features["macho_function_starts"] = []

        self.features["macho_segment_split_info_offset"] = []
        self.features["macho_segment_split_info_size"] = []

        self.features["macho_subframework_umbrella_name"] = []

        self.features["macho_dynamic_linker_environment"] = []

        self.features["macho_encryption_info_offset"] = []
        self.features["macho_encryption_info_size"] = []
        self.features["macho_encryption_info_id"] = []

        lc_counts = dict()
        for command in macho_file.commands:
            command_type = LOAD_COMMAND_TYPES(command.command, str(int(command.command)))

            # count the type
            command_count = lc_counts.get(command_type, 0)
            lc_counts[command_type] = command_count + 1

            # ensure table doesn't get too big
            if command.command_offset > BIG_INT_MAX:
                self.features.setdefault("tag", set()).add("macho_excessive_load_command_table")
                continue

            command_offset = str(command.command_offset)
            # extract common features to all load commands
            self.features["macho_load_command_offset"].append(command.command_offset)
            self.features["macho_load_command_type"].append(FV(command_type, label=command_offset))
            self.features["macho_load_command_size"].append(FV(command.size, label=command_offset))
            self.features["macho_load_command_hash"].append(
                FV(md5(bytearray(command.data)).hexdigest(), label=command_offset)  # noqa: S303, S324
            )

            # pass to handler
            handler = handlers.get(command_type, None)
            if handler:
                handler(command)

        self.features["macho_load_command"] = list(lc_counts.keys())
        self.features["macho_load_command_count"] = list(FV(v, label=k) for k, v in lc_counts.items())

    def _handle_macho_lc_segment_command(self, command):
        """Extract information from Mach-O SEGMENT and SEGMENT_64 load commands."""
        if not isinstance(command, MachO.SegmentCommand):
            raise TypeError("Expected SegmentCommand")

        name = command.name
        self.features["macho_segment_name"].append(FV(name, offset=command.file_offset, size=command.file_size))
        if command.virtual_address <= BIG_INT_MAX:
            self.features["macho_segment_virtual_address"].append(FV(command.virtual_address, label=name))
        else:
            self.features.setdefault("tag", set()).add("macho_segment_kernel_virtual_address")

        if command.virtual_size <= BIG_INT_MAX:
            self.features["macho_segment_virtual_size"].append(FV(command.virtual_size, label=name))
        else:
            self.features.setdefault("tag", set()).add("macho_excessive_segment_virtual_size")

        if command.file_size <= BIG_INT_MAX:
            self.features["macho_segment_raw_size"].append(FV(command.file_size, label=name))
        else:
            self.features.setdefault("tag", set()).add("macho_excessive_segment_raw_size")

        if command.file_offset <= BIG_INT_MAX:
            self.features["macho_segment_raw_offset"].append(FV(command.file_offset, label=name))
        else:
            self.features.setdefault("tag", set()).add("macho_excessive_segment_raw_offset")

        self.features["macho_segment_max_protection"].append(FV("{:08x}".format(command.max_protection), label=name))

        self.features["macho_segment_init_protection"].append(FV("{:08x}".format(command.init_protection), label=name))
        self.features["macho_segment_flags"].append(FV("{:08x}".format(command.flags), label=name))
        self.features["macho_segment_sections_count"].append(FV(command.numberof_sections, label=name))
        self.features["macho_segment_relocations_count"].append(FV(len(command.relocations), label=name))
        self.features["macho_segment_hash"].append(
            FV(md5(bytearray(command.content)).hexdigest(), label=name)  # noqa: S303, S324
        )

        for section in command.sections:
            sec_name = "{segment_name}.{section_name}".format(segment_name=command.name, section_name=section.name)
            self.features["macho_section_name"].append(FV(section.name, label=name))
            self.features["macho_section_fullname"].append(sec_name)

            if section.size <= BIG_INT_MAX:
                self.features["macho_section_size"].append(FV(section.size, label=sec_name))
            else:
                self.features.setdefault("tag", set()).add("macho_excessive_section_size")

            if section.offset <= BIG_INT_MAX:
                self.features["macho_section_virtual_address"].append(FV(section.virtual_address, label=sec_name))
            else:
                self.features.setdefault("tag", set()).add("macho_section_kernel_virtual_address")

            self.features["macho_section_offset"].append(FV(section.offset, label=sec_name))
            self.features["macho_section_alignment"].append(FV(section.alignment, label=sec_name))
            self.features["macho_section_relocations_offset"].append(FV(section.relocation_offset, label=sec_name))
            self.features["macho_section_relocations_count"].append(FV(section.numberof_relocations, label=sec_name))
            sec_type = section.type.name
            if sec_type:
                self.features["macho_section_type"].append(FV(sec_type, label=sec_name))
            self.features["macho_section_reserved"].append(
                FV(
                    "{:08x}.{:08x}.{:08x}".format(section.reserved1, section.reserved2, section.reserved3),
                    label=sec_name,
                )
            )
            self.features["macho_section_flag"].extend(FV(flag.name, label=sec_name) for flag in section.flags_list)

            if section.content is None or isinstance(section.content, lief.lief_errors):
                self.features.setdefault("tag", set()).add("macho_invalid_section")
            else:
                data = bytearray(section.content)
                section_hash = md5(data).hexdigest()  # noqa: S303, S324
                self.features["macho_section_hash"].append(FV(section_hash, label=sec_name))

    def _handle_macho_lc_dylib_command(self, command):
        """Extract information from Mach-O dylib load commands.

        Specifically these include LOAD_WEAK_DYLIB, ID_DYLIB, LOAD_DYLIB,
        REEXPORT_DYLIB, LOAD_UPWARD_DYLIB and LAZY_LOAD_DYLIB commands.
        """
        if not isinstance(command, MachO.DylibCommand):
            raise TypeError("Expected DylibCommand")

        name = command.name
        self.features["macho_dylib_name"].append(Filepath(name))
        self.features["macho_dylib_timestamp"].append(FV(command.timestamp, label=name))
        self.features["macho_dylib_current_version"].append(
            FV("{}.{}.{}".format(*command.current_version), label=name)
        )
        self.features["macho_dylib_compat_version"].append(
            FV("{}.{}.{}".format(*command.compatibility_version), label=name)
        )

    def _handle_macho_lc_rpath_command(self, command):
        """Extract information from Mach-O RPATH load command."""
        if not isinstance(command, MachO.RPathCommand):
            raise TypeError("Expected RPathCommand")

        self.features["macho_rpath"].append(command.path)

    def _handle_macho_lc_uuid_command(self, command):
        """Extract information from Mach-O UUID load command."""
        if not isinstance(command, MachO.UUIDCommand):
            raise TypeError("Expected UUIDCommand")

        uuid = str(UUID(bytes_le=bytes(bytearray(command.uuid))))
        self.features["macho_uuid"].append(uuid)

    def _handle_macho_lc_dylinker_command(self, command):
        """Extract information from Mach-O LOAD_DYLINKER and ID_DYLINKER load commands."""
        if not isinstance(command, MachO.DylinkerCommand):
            raise TypeError("Expected DylinkerCommand")

        self.features["macho_dynamic_linker_name"].append(command.name)

    def _handle_macho_lc_thread_command(self, command):
        """Extract information from Mach-O THREAD and UNIXTHREAD load commands."""
        if not isinstance(command, MachO.ThreadCommand):
            raise TypeError("Expected ThreadCommand")

        state_hash = md5(bytearray(command.state)).hexdigest()  # noqa: S303, S324
        self.features["macho_thread_state_hash"].append(state_hash)
        self.features["macho_thread_flavor"].append(FV(command.flavor, label=state_hash))
        self.features["macho_thread_count"].append(FV(command.count, label=state_hash))
        if command.pc <= BIG_INT_MAX:
            self.features["macho_thread_pc"].append(FV(command.pc, label=state_hash))
        else:
            self.features.setdefault("tag", set()).add("macho_thread_kernel_entrypoint")

    def _handle_macho_lc_symtab_command(self, command):
        """Extract information from Mach-O SYMTAB load command."""
        if not isinstance(command, MachO.SymbolCommand):
            raise TypeError("Expected SymbolCommand")

        offset = str(command.symbol_offset)
        self.features["macho_symbol_table_offset"].append(command.symbol_offset)
        self.features["macho_symbol_table_symbols_count"].append(FV(command.numberof_symbols, label=offset))
        self.features["macho_symbol_table_strings_offset"].append(FV(command.strings_offset, label=offset))
        self.features["macho_symbol_table_strings_size"].append(FV(command.strings_size, label=offset))

    def _handle_macho_lc_dysymtab_command(self, command):
        """Extract information from Mach-O DYSYMTAB load command."""
        if not isinstance(command, MachO.DynamicSymbolCommand):
            raise TypeError("Expected DynamicSymbolCommand")

        self.features["macho_dynamic_symbol_local_index"].append(command.idx_local_symbol)
        self.features["macho_dynamic_symbol_local_count"].append(
            FV(command.nb_local_symbols, label=str(command.idx_local_symbol))
        )

        self.features["macho_dynamic_symbol_external_defined_index"].append(command.idx_external_define_symbol)
        self.features["macho_dynamic_symbol_external_defined_count"].append(
            FV(command.nb_external_define_symbols, label=str(command.idx_external_define_symbol))
        )

        self.features["macho_dynamic_symbol_undefined_index"].append(command.idx_undefined_symbol)
        self.features["macho_dynamic_symbol_undefined_count"].append(
            FV(command.nb_undefined_symbols, label=str(command.idx_undefined_symbol))
        )

        self.features["macho_dynamic_symbol_toc_offset"].append(command.toc_offset)
        self.features["macho_dynamic_symbol_toc_count"].append(FV(command.nb_toc, label=str(command.toc_offset)))

        self.features["macho_dynamic_symbol_module_table_offset"].append(command.module_table_offset)
        self.features["macho_dynamic_symbol_module_table_count"].append(
            FV(command.nb_module_table, label=str(command.module_table_offset))
        )

        self.features["macho_dynamic_symbol_external_reference_offset"].append(
            command.external_reference_symbol_offset
        )
        self.features["macho_dynamic_symbol_external_reference_count"].append(
            FV(command.nb_external_reference_symbols, label=str(command.external_reference_symbol_offset))
        )

        self.features["macho_dynamic_symbol_indirect_symbol_offset"].append(command.indirect_symbol_offset)
        self.features["macho_dynamic_symbol_indirect_symbol_count"].append(
            FV(command.nb_indirect_symbols, label=str(command.indirect_symbol_offset))
        )

        self.features["macho_dynamic_symbol_external_relocation_offset"].append(command.external_relocation_offset)
        self.features["macho_dynamic_symbol_external_relocation_count"].append(
            FV(command.nb_external_relocations, label=str(command.external_relocation_offset))
        )

        self.features["macho_dynamic_symbol_local_relocation_offset"].append(command.local_relocation_offset)
        self.features["macho_dynamic_symbol_local_relocation_count"].append(
            FV(command.nb_local_relocations, label=str(command.local_relocation_offset))
        )

    def _handle_macho_lc_dyld_info_command(self, command):
        """Extract information from Mach-O DYLD_INFO and DYLD_INFO_ONLY load commands."""
        if not isinstance(command, MachO.DyldInfo):
            raise TypeError("Expected DyldInfo")

        offset, size = command.rebase
        self.features["macho_dyld_info_rebase_offset"].append(offset)
        self.features["macho_dyld_info_rebase_size"].append(FV(size, label=str(offset)))
        self.features["macho_dyld_info_rebase_opcodes_hash"].append(
            FV(md5(bytearray(command.rebase_opcodes)).hexdigest(), label=str(offset))  # noqa: S303, S324
        )

        offset, size = command.bind
        self.features["macho_dyld_info_bind_offset"].append(offset)
        self.features["macho_dyld_info_bind_size"].append(FV(size, label=str(offset)))
        self.features["macho_dyld_info_bind_opcodes_hash"].append(
            FV(md5(bytearray(command.bind_opcodes)).hexdigest(), label=str(offset))  # noqa: S303, S324
        )

        offset, size = command.weak_bind
        self.features["macho_dyld_info_weak_bind_offset"].append(offset)
        self.features["macho_dyld_info_weak_bind_size"].append(FV(size, label=str(offset)))
        self.features["macho_dyld_info_weak_bind_opcodes_hash"].append(
            FV(
                md5(bytearray(command.weak_bind_opcodes)).hexdigest(),  # noqa: S303, S324
                label=str(offset),
            )
        )

        offset, size = command.lazy_bind
        self.features["macho_dyld_info_lazy_bind_offset"].append(offset)
        self.features["macho_dyld_info_lazy_bind_size"].append(FV(size, label=str(offset)))
        self.features["macho_dyld_info_lazy_bind_opcodes_hash"].append(
            FV(
                md5(bytearray(command.lazy_bind_opcodes)).hexdigest(),  # noqa: S303, S324
                label=str(offset),
            )
        )

        offset, size = command.export_info
        self.features["macho_dyld_info_export_offset"].append(offset)
        self.features["macho_dyld_info_export_size"].append(FV(size, label=str(offset)))

        for export in command.exports:
            name = export.symbol.name
            self.features["macho_export_name"].append(name)

            sym_kind = export.kind.name
            if sym_kind:
                self.features["macho_export_kind"].append(FV(sym_kind, label=name))
            self.features["macho_export_flag"].extend(FV(flag.name, label=name) for flag in export.flags_list)

            if export.address <= BIG_INT_MAX:
                self.features["macho_export_address"].append(FV(export.address, label=name))
            else:
                self.features.setdefault("tag", set()).add("macho_export_kernel_address")

            if export.alias is not None:
                self.features["macho_export_alias_name"].append(FV(export.alias.name, label=name))
            if export.alias_library is not None:
                self.features["macho_export_alias_library_name"].append(FV(export.alias_library.name, label=name))

    def _handle_macho_lc_source_version_command(self, command):
        """Extract information from Mach-O SOURCE_VERSION load command."""
        if not isinstance(command, MachO.SourceVersion):
            raise TypeError("Expected SourceVersion")

        self.features["macho_source_version"].append("{}.{}.{}.{}.{}".format(*command.version))

    def _handle_macho_lc_version_min_command(self, command):
        """Extract information from Mach-O VERSION_MIN_MACOSX and VERSION_MIN_IPHONEOS load commands."""
        if not isinstance(command, MachO.VersionMin):
            raise TypeError("Expected VersionMin")

        self.features["macho_minimum_version"].append("{}.{}.{}".format(*command.version))
        self.features["macho_minimum_sdk_version"].append("{}.{}.{}".format(*command.sdk))

    def _handle_macho_lc_code_signature_command(self, command):
        """Extract information from Mach-O DYLIB_CODE_SIGN_DRS and CODE_SIGNATURE load commands."""
        if not isinstance(command, MachO.CodeSignature) and not isinstance(command, MachO.CodeSignatureDir):
            raise TypeError("Expected CodeSignature")

        self.features["macho_code_signature_offset"].append(command.data_offset)
        self.features["macho_code_signature_size"].append(FV(command.data_size, label=str(command.data_offset)))

    def _handle_macho_lc_data_in_code_command(self, command):
        """Extract information from Mach-O DATA_IN_CODE load command."""
        if not isinstance(command, MachO.DataInCode):
            raise TypeError("Expected DataInCode")

        self.features["macho_data_in_code_offset"].append(command.data_offset)
        self.features["macho_data_in_code_size"].append(FV(command.data_size, label=str(command.data_offset)))

        data_types = {}
        for data in command.entries:
            data_type = data.type.name
            if data_type is None:
                continue

            count, max_length = data_types.get(data_type, (0, 0))

            count += 1
            if data.length > max_length:
                max_length = data.length

            data_types[data_type] = (count, max_length)

        self.features["macho_data_in_code_type"].extend(data_types.keys())
        self.features["macho_data_in_code_type_count"].extend(FV(v[0], label=k) for k, v in data_types.items())
        self.features["macho_data_in_code_type_max_length"].extend(FV(v[1], label=k) for k, v in data_types.items())

    def _handle_macho_lc_main_command(self, command):
        """Extract information from Mach-O MAIN load command."""
        if not isinstance(command, MachO.MainCommand):
            raise TypeError("Expected MainCommand")

        if command.entrypoint <= BIG_INT_MAX:
            self.features["macho_main_entrypoint"].append(command.entrypoint)
        else:
            self.features.setdefault("tag", set()).add("macho_main_kernel_entrypoint")

        if command.stack_size <= BIG_INT_MAX:
            self.features["macho_main_stack_size"].append(FV(command.stack_size, label=str(command.entrypoint)))
        else:
            self.features.setdefault("tag", set()).add("macho_excessive_main_stack_size")

    def _handle_macho_lc_function_starts_command(self, command):
        """Extract information from Mach-O FUNCTION_STARTS load command."""
        if not isinstance(command, MachO.FunctionStarts):
            raise TypeError("Expected FunctionStarts")

        self.features["macho_function_starts_offset"].append(command.data_offset)
        self.features["macho_function_starts_size"].append(FV(command.data_size, label=str(command.data_offset)))
        self.features["macho_function_starts"].append(len(command.functions))

    def _handle_macho_lc_segment_split_info_command(self, command):
        """Extract information from Mach-O SEGMENT_SPLIT_INFO load command."""
        if not isinstance(command, MachO.SegmentSplitInfo):
            raise TypeError("Expected SegmentSplitInfo")

        self.features["macho_segment_split_info_offset"].append(command.data_offset)
        self.features["macho_segment_split_info_size"].append(FV(command.data_size, label=str(command.data_offset)))

    def _handle_macho_lc_sub_framework_command(self, command):
        """Extract information from Mach-O SUB_FRAMEWORK load command."""
        if not isinstance(command, MachO.SubFramework):
            raise TypeError("Expected SubFramework")

        self.features["macho_sub_framework_umbrella_name"].append(command.umbrella)

    def _handle_macho_lc_dyld_environment_command(self, command):
        """Extract information from Mach-O DYLD_ENVIRONMENT load command."""
        if not isinstance(command, MachO.DyldEnvironment):
            raise TypeError("Expected DyldEnvironment")

        self.features["macho_dynamic_linker_environment"].append(command.value)

    def _handle_macho_lc_encryption_info_command(self, command):
        """Extract information from Mach-O ENCRYPTION_INFO and ENCRYPTION_INFO_64 load commands."""
        if not isinstance(command, MachO.EncryptionInfo):
            raise TypeError("Expected EncryptionInfo")

        self.features["macho_encryption_info_offset"].append(command.crypt_offset)
        self.features["macho_encryption_info_size"].append(FV(command.crypt_size, label=str(command.crypt_offset)))
        self.features["macho_encryption_info_id"].append(FV(command.crypt_id, label=str(command.crypt_offset)))


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginLiefMachO)


if __name__ == "__main__":
    main()
