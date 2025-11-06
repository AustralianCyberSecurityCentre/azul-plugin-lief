"""LIEF ELF Plugin.

This plugin uses the library to instrument executable formats (LIEF) to extract
information from ELF files. Information extracted includes:
 - header data
 - section/segment data
 - note parsing (where available)
"""

import contextlib
from hashlib import sha256

import lief
from azul_runner import (
    FV,
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    add_settings,
    cmdline_run,
)
from elftools.elf import descriptions, enums
from elftools.elf.constants import SH_FLAGS
from lief import ELF
from lief.ELF import AndroidIdent, CorePrPsInfo, NoteAbi


class LiefELF(BinaryPlugin):
    """Parse ELF binaries with LIEF."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.10.07"
    SETTINGS = add_settings(
        # FUTURE - may be missing ARM Coredumps unsure what type they will come under.
        filter_data_types={
            "content": [
                # Linux elf or so files
                "executable/linux/"
            ]
        }
    )
    FEATURES = [
        Feature(name="tag", desc="Any informational label about the binary", type=FeatureType.String),
        # Header
        Feature(name="elf_class", desc="Identifies the architecture", type=FeatureType.String),
        Feature(
            name="elf_data", desc="Data encoding of the processor-specific data in the file", type=FeatureType.String
        ),
        Feature(name="elf_hdr_version", desc="Version number of the ELF specification", type=FeatureType.String),
        Feature(name="elf_os_abi", desc="Identifies the operating system and ABI", type=FeatureType.String),
        Feature(
            name="elf_abi_version", desc="Version of the ABI to which the object is targeted", type=FeatureType.Integer
        ),
        Feature(name="elf_type", desc="Object file type", type=FeatureType.String),
        Feature(name="elf_machine", desc="Required architecture for the file", type=FeatureType.String),
        Feature(name="elf_obj_version", desc="File version", type=FeatureType.String),
        Feature(
            name="elf_num_prog_headers", desc="Number of entries in the program header table", type=FeatureType.Integer
        ),
        Feature(
            name="elf_num_section_headers",
            desc="Number of entries in the section header table",
            type=FeatureType.Integer,
        ),
        Feature(name="elf_entrypoint", desc="Virtual address of the entry point", type=FeatureType.Integer),
        Feature(name="elf_program_header_offset", desc="Program header table's file offset", type=FeatureType.Integer),
        Feature(name="elf_program_header_size", desc="Program header table entry size", type=FeatureType.Integer),
        Feature(name="elf_section_header_offset", desc="Section header table's file offset", type=FeatureType.Integer),
        Feature(name="elf_section_header_size", desc="Section header entry size", type=FeatureType.Integer),
        Feature(name="elf_processor_flag", desc="Processor-specific flags", type=FeatureType.Integer),
        Feature(name="elf_header_size", desc="ELF header size", type=FeatureType.Integer),
        Feature(name="elf_section_name_table_idx", desc="Section header string table index", type=FeatureType.Integer),
        # Section
        Feature(name="elf_section", desc="Section name", type=FeatureType.String),
        Feature(name="elf_section_alignment", desc="Section alignment", type=FeatureType.Integer),
        Feature(name="elf_section_entropy", desc="Section entropy", type=FeatureType.Float),
        Feature(name="elf_section_entry_size", desc="Size of fixed-size entries", type=FeatureType.Integer),
        Feature(
            name="elf_section_num_flags",
            desc="Number of flags that describe miscellaneous section attributes",
            type=FeatureType.Integer,
        ),
        Feature(
            name="elf_section_flags", desc="Flags that describe miscellaneous attributes", type=FeatureType.String
        ),
        Feature(name="elf_section_information", desc="Extra information on the section", type=FeatureType.Integer),
        Feature(name="elf_section_link", desc="Section header table index link", type=FeatureType.Integer),
        Feature(
            name="elf_section_type", desc="Categorises the section's contents and semantics", type=FeatureType.String
        ),
        Feature(
            name="elf_section_virtual_address",
            desc="Address where the section will be mapped in memory",
            type=FeatureType.Integer,
        ),
        Feature(name="elf_section_hash", desc="MD5 of the contents of the section", type=FeatureType.String),
        Feature(
            name="elf_section_segments", desc="Segments associated with the given section", type=FeatureType.String
        ),
        # Segment
        Feature(name="elf_segment", desc="Number of segment in the file", type=FeatureType.Integer),
        Feature(name="elf_segment_type", desc="Kind of segment described", type=FeatureType.String),
        Feature(
            name="elf_segment_physical_address",
            desc="Physical address of beginning of segment",
            type=FeatureType.Integer,
        ),
        Feature(
            name="elf_segment_virtual_address",
            desc="Address where the segment will be mapped",
            type=FeatureType.Integer,
        ),
        Feature(name="elf_segment_virtual_size", desc="Size of this segment in memory", type=FeatureType.Integer),
        Feature(
            name="elf_segment_alignment",
            desc="The value to which the segments are aligned in memory and in the file.",
            type=FeatureType.Integer,
        ),
        Feature(name="elf_segment_flags", desc="Segment's flags", type=FeatureType.String),
        Feature(name="elf_segment_sections", desc="Sections inside this segment", type=FeatureType.String),
        # Imports
        Feature(name="elf_import", desc="Import name", type=FeatureType.String),
        Feature(name="elf_import_type", desc="Import type", type=FeatureType.String),
        Feature(name="elf_import_value", desc="Import value", type=FeatureType.Integer),
        Feature(name="elf_import_size", desc="Import size", type=FeatureType.Integer),
        Feature(name="elf_import_visibility", desc="Import visibility", type=FeatureType.String),
        Feature(name="elf_import_binding", desc="Import binding attribute", type=FeatureType.String),
        Feature(name="elf_import_version", desc="Import version", type=FeatureType.String),
        # Exports
        Feature(name="elf_export", desc="Export name", type=FeatureType.String),
        Feature(name="elf_export_type", desc="Export type", type=FeatureType.String),
        Feature(name="elf_export_value", desc="Export value", type=FeatureType.Integer),
        Feature(name="elf_export_size", desc="Export size", type=FeatureType.Integer),
        Feature(name="elf_export_visibility", desc="Export visibility", type=FeatureType.String),
        Feature(name="elf_export_binding", desc="Export binding attribute", type=FeatureType.String),
        Feature(name="elf_export_version", desc="Export version", type=FeatureType.String),
        # Notes
        Feature(name="elf_note", desc="Note index", type=FeatureType.Integer),
        Feature(name="elf_note_name", desc="Name of the note", type=FeatureType.String),
        Feature(name="elf_note_type", desc="Type of the note", type=FeatureType.String),
        Feature(name="elf_note_description", desc="Description of the note", type=FeatureType.String),
        Feature(name="elf_note_version", desc="Version of the note", type=FeatureType.String),
        Feature(name="elf_note_sdk_version", desc="Android: target SDK version", type=FeatureType.String),
        Feature(
            name="elf_note_ndk_version", desc="Android: NDK version used to build the binary", type=FeatureType.String
        ),
        Feature(name="elf_note_ndk_build_number", desc="Android: NDK build number", type=FeatureType.String),
        Feature(name="elf_note_abi", desc="Note ABI", type=FeatureType.String),
        Feature(name="elf_note_gold_version", desc="Gold: linker version", type=FeatureType.String),
        Feature(name="elf_note_coredump_filename", desc="Coredump: Process file name", type=FeatureType.String),
        Feature(name="elf_note_coredump_flags", desc="Coredump: Process flags", type=FeatureType.Integer),
        Feature(name="elf_note_coredump_gid", desc="Coredump: Process group ID", type=FeatureType.Integer),
        Feature(name="elf_note_coredump_pgrp", desc="Coredump: Process session group ID", type=FeatureType.Integer),
        Feature(name="elf_note_coredump_pid", desc="Coredump: Process ID", type=FeatureType.Integer),
        Feature(name="elf_note_coredump_ppid", desc="Coredump: Process parent ID", type=FeatureType.Integer),
        Feature(name="elf_note_coredump_sid", desc="Coredump: Process session ID", type=FeatureType.Integer),
        Feature(name="elf_note_coredump_uid", desc="Coredump: Process user ID", type=FeatureType.Integer),
    ]

    def execute(self, job: Job):
        """Process any ELF file and attempt to parse using LIEF."""
        self.features = {}

        buf = job.get_data()

        elf_file = ELF.parse(buf.get_filepath())
        if not elf_file or isinstance(elf_file, lief.lief_errors):
            self.features["tag"] = "elf_invalid"
        else:
            # Process ELF features now that LIEF has successfully completed:
            self._handle_header(elf_file)
            self._handle_sections(elf_file)
            self._handle_segments(elf_file)
            self._handle_dynamic_symbols(elf_file)
            self._handle_notes(elf_file)

        self.add_many_feature_values(self.features)

    def _handle_header(self, elf_file: ELF.Binary):
        """Extract features from ELF header."""
        self.features["elf_class"] = str(elf_file.header.identity_class).split(".")[-1]
        self._set_desc_by_feature("elf_data", elf_file.header.identity_data)
        self._set_desc_by_feature("elf_hdr_version", elf_file.header.identity_version)
        self._set_desc_by_feature("elf_os_abi", elf_file.header.identity_os_abi)
        self.features["elf_abi_version"] = elf_file.header.identity_abi_version
        self._set_desc_by_feature("elf_type", elf_file.header.file_type)
        self._set_desc_by_feature("elf_machine", elf_file.header.machine_type)
        self._set_desc_by_feature("elf_obj_version", elf_file.header.object_file_version)
        self.features["elf_num_prog_headers"] = elf_file.header.numberof_segments
        self.features["elf_num_section_headers"] = elf_file.header.numberof_sections
        self.features["elf_entrypoint"] = elf_file.header.entrypoint
        self.features["elf_program_header_offset"] = elf_file.header.program_header_offset
        self.features["elf_program_header_size"] = elf_file.header.program_header_size
        self.features["elf_section_header_offset"] = elf_file.header.section_header_offset
        self.features["elf_section_header_size"] = elf_file.header.section_header_size
        self.features["elf_processor_flag"] = elf_file.header.processor_flag
        self.features["elf_header_size"] = elf_file.header.header_size
        self.features["elf_section_name_table_idx"] = elf_file.header.section_name_table_idx

    def _handle_sections(self, elf_file: ELF.Binary):
        self.features["elf_section"] = []
        self.features["elf_section_alignment"] = []
        self.features["elf_section_entropy"] = []
        self.features["elf_section_entry_size"] = []
        self.features["elf_section_num_flags"] = []
        self.features["elf_section_flags"] = []
        self.features["elf_section_information"] = []
        self.features["elf_section_link"] = []
        self.features["elf_section_type"] = []
        self.features["elf_section_virtual_address"] = []
        self.features["elf_section_hash"] = []
        self.features["elf_section_segments"] = []

        for section in elf_file.sections:
            self.features["elf_section"].append(FV(section.name, offset=section.file_offset, size=section.size))
            self.features["elf_section_alignment"].append(FV(section.alignment, label=section.name))
            self.features["elf_section_entropy"].append(FV(section.entropy, label=section.name))
            self.features["elf_section_entry_size"].append(FV(section.entry_size, label=section.name))
            self.features["elf_section_num_flags"].append(FV(section.flags, label=section.name))
            self._append_flags_by_feature("elf_section_flags", section.flags_list, section.name)
            self.features["elf_section_information"].append(FV(section.information, label=section.name))
            self.features["elf_section_link"].append(FV(section.link, label=section.name))

            self._append_desc_by_feature("elf_section_type", section.type, section.name)
            self.features["elf_section_virtual_address"].append(FV(section.virtual_address, label=section.name))
            data = bytearray(section.content)
            section_hash = sha256(data).hexdigest()
            self.features["elf_section_hash"].append(FV(section_hash, label=section.name))

            section_segments = " - ".join([str(s.type).split(".")[-1] for s in section.segments])
            self.features["elf_section_segments"].append(FV(section_segments, label=section.name))

    def _handle_segments(self, elf_file: ELF.Binary):
        self.features["elf_segment"] = []
        self.features["elf_segment_type"] = []
        self.features["elf_segment_physical_address"] = []
        self.features["elf_segment_virtual_address"] = []
        self.features["elf_segment_virtual_size"] = []
        self.features["elf_segment_alignment"] = []
        self.features["elf_segment_flags"] = []
        self.features["elf_segment_sections"] = []

        for segment_num, segment in enumerate(elf_file.segments):
            # Drop integer virtual addresses larger than a long int.
            if segment.virtual_address > 9223372036854775807:
                continue

            self.features["elf_segment"].append(
                FV(segment_num, offset=segment.file_offset, size=segment.physical_size)
            )
            segment_num = str(segment_num)  # FV labels must be of type str
            self._append_desc_by_feature("elf_segment_type", segment.type, segment_num)
            self.features["elf_segment_physical_address"].append(FV(segment.physical_address, label=segment_num))
            self.features["elf_segment_virtual_address"].append(FV(segment.virtual_address, label=segment_num))
            self.features["elf_segment_virtual_size"].append(FV(segment.virtual_size, label=segment_num))
            self.features["elf_segment_alignment"].append(FV(segment.alignment, label=segment_num))

            # Build flags string
            flags_str = ["-"] * 3
            if ELF.Segment.FLAGS.R in segment:
                flags_str[0] = "R"

            if ELF.Segment.FLAGS.W in segment:
                flags_str[1] = "W"

            if ELF.Segment.FLAGS.X in segment:
                flags_str[2] = "X"
            flags_str = "".join(flags_str)
            self.features["elf_segment_flags"].append(FV(flags_str, label=segment_num))

            segment_sections = ", ".join([section.name for section in segment.sections])
            self.features["elf_segment_sections"].append(FV(segment_sections, label=segment_num))

    def _handle_dynamic_symbols(self, elf_file: ELF.Binary):
        self.features["elf_import"] = []
        self.features["elf_import_type"] = []
        self.features["elf_import_value"] = []
        self.features["elf_import_size"] = []
        self.features["elf_import_visibility"] = []
        self.features["elf_import_binding"] = []
        self.features["elf_import_version"] = []
        self.features["elf_export"] = []
        self.features["elf_export_type"] = []
        self.features["elf_export_value"] = []
        self.features["elf_export_size"] = []
        self.features["elf_export_visibility"] = []
        self.features["elf_export_binding"] = []
        self.features["elf_export_version"] = []

        # Limit number of symbols exported due to Azul limitation
        for symbol in list(elf_file.dynamic_symbols)[0 : self.cfg.max_values_per_feature]:
            # From elf_reader.py
            try:
                symbol_name = symbol.demangled_name
            except AttributeError:
                symbol_name = symbol.name
            direction = ""
            if symbol.imported:
                direction = "import"
            if symbol.exported:
                direction = "export"

            if symbol.name and direction:
                self.features[f"elf_{direction}"].append(FV(symbol_name))
                self.features[f"elf_{direction}_type"].append(FV(str(symbol.type).split(".")[-1], label=symbol.name))
                self.features[f"elf_{direction}_value"].append(FV(symbol.value, label=symbol.name))
                self.features[f"elf_{direction}_size"].append(FV(symbol.size, label=symbol.name))
                self.features[f"elf_{direction}_visibility"].append(
                    FV(str(symbol.visibility).split(".")[-1], label=symbol.name)
                )
                self.features[f"elf_{direction}_binding"].append(
                    FV(str(symbol.binding).split(".")[-1], label=symbol.name)
                )
                version = str(symbol.symbol_version) if symbol.has_version else ""
                self.features[f"elf_{direction}_version"].append(FV(version, label=symbol.name))

    def _handle_notes(self, elf_file: ELF.Binary):
        self.features["elf_note"] = []
        self.features["elf_note_name"] = []
        self.features["elf_note_type"] = []
        self.features["elf_note_description"] = []
        self.features["elf_note_version"] = []
        self.features["elf_note_sdk_version"] = []
        self.features["elf_note_ndk_version"] = []
        self.features["elf_note_ndk_build_number"] = []
        self.features["elf_note_abi"] = []
        self.features["elf_note_gold_version"] = []
        self.features["elf_note_coredump_filename"] = []
        self.features["elf_note_coredump_flags"] = []
        self.features["elf_note_coredump_gid"] = []
        self.features["elf_note_coredump_pgrp"] = []
        self.features["elf_note_coredump_pid"] = []
        self.features["elf_note_coredump_ppid"] = []
        self.features["elf_note_coredump_sid"] = []
        self.features["elf_note_coredump_uid"] = []

        for note_index, note in enumerate(elf_file.notes):
            self.features["elf_note"].append(FV(note_index))
            note_index = str(note_index)
            # If the note name is invalid unicode drop it.
            with contextlib.suppress(UnicodeDecodeError):
                self.features["elf_note_name"].append(FV(note.name, label=note_index))
            type_str = note.type.__name__
            self.features["elf_note_type"].append(FV(type_str, label=note_index))
            description_str = " ".join(map(lambda e: "{:02x}".format(e), note.description))
            self.features["elf_note_description"].append(FV(description_str, label=note_index))
            if isinstance(note, NoteAbi):
                version = note.version
                if version:
                    version_str = "{:d}.{:d}.{:d}".format(version[0], version[1], version[2])
                    self.features["elf_note_version"].append(FV(version_str, label=note_index))
                if note.abi:
                    self.features["elf_note_abi"].append(FV(str(note.abi.__name__), label=note_index))

            if isinstance(note, AndroidIdent):
                self.features["elf_note_sdk_version"].append(FV(str(note.sdk_version).strip("\x00"), label=note_index))
                self.features["elf_note_ndk_version"].append(FV(str(note.ndk_version).strip("\x00"), label=note_index))
                self.features["elf_note_ndk_build_number"].append(
                    FV(str(note.ndk_build_number).strip("\x00"), label=note_index)
                )

            # FUTURE: This may no longer be useful or the type check may be dropped in the future.
            if note.type == ELF.Note.TYPE.GNU_GOLD_VERSION:
                self.features["elf_note_gold_version"].append(
                    FV("".join(map(chr, note.description)).strip("\x00"), label=note_index)
                )

            # Coredumps on Linux are ELFs - there is a large document in here with e.g. register contents and
            # the like (CorePrStatus), but instead just extracting some core features:
            if isinstance(note, CorePrPsInfo):
                self.features["elf_note_coredump_filename"].append(FV(note.info.filename_stripped, label=note_index))
                self.features["elf_note_coredump_flags"].append(FV(note.info.flag, label=note_index))
                self.features["elf_note_coredump_gid"].append(FV(note.info.gid, label=note_index))
                self.features["elf_note_coredump_pgrp"].append(FV(note.info.pgrp, label=note_index))
                self.features["elf_note_coredump_pid"].append(FV(note.info.pid, label=note_index))
                self.features["elf_note_coredump_ppid"].append(FV(note.info.ppid, label=note_index))
                self.features["elf_note_coredump_sid"].append(FV(note.info.sid, label=note_index))
                self.features["elf_note_coredump_uid"].append(FV(note.info.uid, label=note_index))

    # Helper functions

    def _set_desc_by_feature(self, feature, value):
        self.features[feature] = []
        self._append_desc_by_feature(feature, value, None)
        return self.features[feature]

    def _append_desc_by_feature(self, feature, value, label: str | None):
        value = int(value)
        if label:
            label = str(label)
        desc_func_name, enum_name = ENUM_DESCRIPION[feature]
        d_func = getattr(descriptions, desc_func_name)
        enum = getattr(enums, enum_name)
        key = next((k for k, v in enum.items() if v == value), None)
        try:
            self.features[feature].append(FV(d_func(key), label=label))
        except (KeyError, TypeError):
            self.features[feature].append(FV("<unknown>", label=label))

    def _append_flags_by_feature(self, feature: str, flag_list: list[SH_FLAGS], label: str):
        d_func = getattr(descriptions, FLAG_DESCRIPTION[feature])
        flags = []
        try:
            for flag in flag_list:
                flags.append(d_func(flag.value))
        except TypeError:
            flags = ["<unknown>"]
        self.features[feature].append(FV("".join(flags), label=label))


ENUM_DESCRIPION = {
    "elf_data": ("describe_ei_data", "ENUM_EI_DATA"),
    "elf_hdr_version": ("describe_ei_version", "ENUM_E_VERSION"),
    "elf_os_abi": ("describe_ei_osabi", "ENUM_EI_OSABI"),
    "elf_type": ("describe_e_type", "ENUM_E_TYPE"),
    "elf_machine": ("describe_e_machine", "ENUM_E_MACHINE"),
    "elf_obj_version": ("describe_e_version_numeric", "ENUM_E_VERSION"),
    "elf_section_type": ("describe_sh_type", "ENUM_SH_TYPE_BASE"),
    "elf_segment_type": ("describe_p_type", "ENUM_P_TYPE_BASE"),
}
FLAG_DESCRIPTION = {
    "elf_section_flags": ("describe_sh_flags"),
}


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=LiefELF)


if __name__ == "__main__":
    main()
