"""Parse and extract PE headers, sections, resources and more with LIEF.

This plugin uses the library to instrument executable formats (LIEF) to extract
information from PE files. Information extracted includes:
 - header data
 - sections
 - resources
 - imports and exports
 - slack space
"""

import contextlib
import io
import itertools
from datetime import UTC, datetime
from hashlib import md5, sha256
from uuid import UUID

import lief
from azul_runner import (
    BinaryPlugin,
    Feature,
    FeatureType,
    FeatureValue,
    Filepath,
    Job,
    StorageProxyFile,
    add_settings,
    cmdline_run,
    plugin_executor,
)
from lief import PE


def enum_wrapper(lief_enum):
    """Wrap a lief enum to allow getting the name of the enum rather than the Enum itself."""

    def get_enum_name_or_none(value: int, default=None) -> str | None:
        """Get the name of an enum or the default value if that fails."""
        try:
            return lief_enum.from_value(value).__name__
        except Exception:
            return default

    return get_enum_name_or_none


def is_repeated_byte_file(raw_bytes: bytes) -> bool:
    """Check if a file is full or repeated bytes or really small and returns True if it's not a useful file."""
    # If the file is 3 bytes long it isn't a good file any way.
    if len(raw_bytes) < 3:
        return True
    first_byte = raw_bytes[0]
    second_byte = raw_bytes[1]
    for b in raw_bytes:
        if b == first_byte:
            continue
        elif b == second_byte:
            continue
        else:
            # File is not just repeated bytes.
            return False
    return True


BIG_INT_MAX = (1 << 63) - 1
RESOURCE_TYPES = enum_wrapper(PE.ResourcesManager.TYPE)
RESOURCE_LANGS = enum_wrapper(PE.RESOURCE_LANGS)


class AzulPluginLiefPE(BinaryPlugin):
    """Parse and extract PE headers, sections, resources and more with LIEF."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.10.07"
    SETTINGS = add_settings(
        # How many child resources should be extracted before stopping.
        # Limited otherwise you can get thousands of useless child binary resources.
        max_resource_extraction=(int, 30),
        # Limit some feature values to a low number as they aren't too important for pivoting but we want to keep some.
        max_values_per_less_important_feature=(int, 400),
        # Overriding the runner defaults because some feature values can be quite high and liefPE is self limiting it's
        # Large Feature value pairs.
        max_values_per_feature=(int, 4000),
        filter_data_types={
            "content": [
                # Windows exe
                "executable/windows/pe",
                "executable/windows/pe32",
                "executable/windows/pe64",
                "executable/windows/dll",
                "executable/windows/dll32",
                "executable/windows/dll64",
                # Non windows exe
                "executable/dll32",
                "executable/pe32",
            ]
        },
    )
    # Ensure any changes are kept in sync with features set by virustotal filemapper
    FEATURES = [
        # Common/generic features
        Feature(name="tag", desc="Any informational label about the binary", type=FeatureType.String),
        Feature(name="pe_dos_stub", desc="Raw MS-DOS stub 16-bit instructions/message", type=FeatureType.Binary),
        # Header features
        Feature(name="pe_compile_time", desc="PE Compile Time", type=FeatureType.Datetime),
        Feature(name="pe_machine", desc="Machine as defined in PE file header", type=FeatureType.String),
        Feature(
            name="pe_characteristics", desc="Characteristics as defined in the PE file header", type=FeatureType.String
        ),
        Feature(
            name="pe_entry_point",
            desc="Entry point address as defined in PE optional header",
            type=FeatureType.Integer,
        ),
        Feature(name="pe_code_base", desc="Code base as defined in PE optional header", type=FeatureType.Integer),
        Feature(name="pe_checksum", desc="Checksum as defined in PE optional header", type=FeatureType.Integer),
        Feature(
            name="pe_dll_characteristics",
            desc="DLL characteristics as defined in PE optional header",
            type=FeatureType.String,
        ),
        Feature(
            name="pe_file_alignment", desc="File alignment as defined in PE optional header", type=FeatureType.Integer
        ),
        Feature(name="pe_image_base", desc="Image base as defined in PE optional header", type=FeatureType.Integer),
        Feature(
            name="pe_loader_flags", desc="Loader flags as defined in PE optional header", type=FeatureType.Integer
        ),
        Feature(
            name="pe_image_version", desc="Image version as defined in PE optional header", type=FeatureType.String
        ),
        Feature(
            name="pe_linker_version", desc="Linker version as defined in PE optional header", type=FeatureType.String
        ),
        Feature(
            name="pe_os_version",
            desc="Operating system version as defined in PE optional header",
            type=FeatureType.String,
        ),
        Feature(
            name="pe_subsystem_version",
            desc="Subsystem version as defined in PE optional header",
            type=FeatureType.String,
        ),
        Feature(
            name="pe_num_rva_and_sizes",
            desc="Number of data directories from PE optional header",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_section_alignment",
            desc="Section alignment as defined in PE optional header",
            type=FeatureType.Integer,
        ),
        Feature(name="pe_code_size", desc="Code size as defined in PE optional header", type=FeatureType.Integer),
        Feature(name="pe_header_size", desc="Header size as defined in PE optional header", type=FeatureType.Integer),
        Feature(
            name="pe_heap_commit_size",
            desc="Heap commit size as defined in PE optional header",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_heap_reserve_size",
            desc="Heap reserve size as defined in PE optional header",
            type=FeatureType.Integer,
        ),
        Feature(name="pe_image_size", desc="Image size as defined in PE optional header", type=FeatureType.Integer),
        Feature(
            name="pe_init_data_size",
            desc="Initialised data size as defined in PE optional header",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_uninit_data_size",
            desc="Uninitialised data size as defined in PE optional header",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_stack_commit_size",
            desc="Stack commit size as defined in PE optional header",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_stack_reserve_size",
            desc="Stack reserve size as defined in PE optional header",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_subsystem", desc="Target subsystem as defined in PE optional header", type=FeatureType.String
        ),
        Feature(
            name="pe_win32_version", desc="Win32 version as defined in PE optional header", type=FeatureType.Integer
        ),
        Feature(name="pe_data_base", desc="Data base as defined in PE optional header", type=FeatureType.Integer),
        # Section features
        Feature(name="pe_section_count", desc="Number of sections", type=FeatureType.Integer),
        Feature(name="pe_section", desc="Name of the PE section", type=FeatureType.String),
        Feature(name="pe_section_virtual_size", desc="Virtual size of the section", type=FeatureType.Integer),
        Feature(name="pe_section_virtual_address", desc="Virtual address of the section", type=FeatureType.Integer),
        Feature(name="pe_section_raw_size", desc="Raw size of the section", type=FeatureType.Integer),
        Feature(name="pe_section_raw_address", desc="Raw file offset of the section", type=FeatureType.Integer),
        Feature(
            name="pe_section_relocs_address",
            desc="Raw file offset of the relocations for the section",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_section_line_nums_address",
            desc="Raw file offset of the line nums for the section",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_section_relocs_count", desc="Number of relocations for the section", type=FeatureType.Integer
        ),
        Feature(
            name="pe_section_line_nums_count", desc="Number of line numbers for the section", type=FeatureType.Integer
        ),
        Feature(name="pe_section_characteristics", desc="Characteristics of the section", type=FeatureType.String),
        Feature(
            name="pe_section_raw_hash",
            desc="MD5 of the contents of the section including any slack",
            type=FeatureType.String,
        ),
        Feature(name="pe_section_hash", desc="MD5 of the contents of the section", type=FeatureType.String),
        # Import features
        Feature(name="pe_import_module_count", desc="Count of modules imported", type=FeatureType.Integer),
        Feature(name="pe_import_module", desc="Name of the module imported", type=FeatureType.String),
        Feature(
            name="pe_import_function_count",
            desc="Count of the functions imported from the module",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_import_function", desc="Name of the function imported from the module", type=FeatureType.String
        ),
        Feature(
            name="pe_import_function_ordinal",
            desc="Ordinal of the function imported from the module",
            type=FeatureType.Integer,
        ),
        Feature(
            name="pe_import_function_fullname",
            desc="Concatenated module and function name/ordinal",
            type=FeatureType.String,
        ),
        Feature(name="pe_import_function_hint", desc="Hint for the labelled function", type=FeatureType.Integer),
        Feature(
            name="pe_import_function_multicount",
            desc="Number of times imported function is included",
            type=FeatureType.Integer,
        ),
        Feature(name="pe_import_hash", desc="MD5 hash of the import entries", type=FeatureType.String),
        Feature(
            name="pe_import_hash_sorted",
            desc="MD5 imports sorted hash as per Quarklabs implementation",
            type=FeatureType.String,
        ),
        # Export features
        Feature(name="pe_export", desc="Name of the DLL exported", type=FeatureType.String),
        Feature(name="pe_export_characteristics", desc="Characteristics of the DLL exported", type=FeatureType.String),
        Feature(name="pe_export_version", desc="Version of the DLL exported", type=FeatureType.String),
        Feature(name="pe_export_time", desc="Time the DLL was exported", type=FeatureType.Datetime),
        Feature(name="pe_export_base", desc="Base ordinal of the exported functions", type=FeatureType.Integer),
        Feature(name="pe_export_count", desc="Number of exported functions", type=FeatureType.Integer),
        Feature(name="pe_export_function", desc="Name of the exported function", type=FeatureType.String),
        # Removed as doesn't make sense for pivoting and confuses similarity scoring
        # i.e. ordinals collide across unrelated samples
        # Feature(name='pe_export_function_ordinal', desc='Ordinal of the exported function', type=FeatureType.Integer)
        Feature(name="pe_export_function_address", desc="Address of the exported function", type=FeatureType.Integer),
        Feature(
            name="pe_export_external_function", desc="Name of external exported function", type=FeatureType.String
        ),
        Feature(
            name="pe_export_external_function_ordinal",
            desc="Ordinal of the external exported function",
            type=FeatureType.Integer,
        ),
        # Overlay features
        Feature(name="pe_overlay_hash", desc="MD5 of the PE overlay", type=FeatureType.String),
        Feature(name="pe_overlay_size", desc="Size of the PE overlay", type=FeatureType.Integer),
        # Resource features
        Feature(
            name="pe_resource", desc="SHA256 hash of the embedded PE resource", type=FeatureType.String
        ),  # VT only includes SHA256
        Feature(
            name="pe_resource_size", desc="Size of the PE resource labelled by resource hash", type=FeatureType.Integer
        ),
        Feature(
            name="pe_resource_name", desc="Name of the PE resource labelled by resource hash", type=FeatureType.String
        ),
        Feature(
            name="pe_resource_type",
            desc="Type of the PE resource labelled by resource hash (no label on unknown resource_types)",
            type=FeatureType.String,
        ),
        Feature(
            name="pe_resource_language",
            desc="Languages that occur in the embedded resources",
            type=FeatureType.String,
        ),
        # Debug Features
        Feature(
            name="pe_debug_characteristics", desc="Characteristics of debug (should be zero)", type=FeatureType.Integer
        ),
        Feature(name="pe_debug_offset", desc="Raw file offset to debug information", type=FeatureType.Integer),
        Feature(name="pe_debug_size", desc="Size of debug record", type=FeatureType.Integer),
        Feature(name="pe_debug_timestamp", desc="Debug data creation time and date", type=FeatureType.Datetime),
        Feature(name="pe_debug_type", desc="Format of debugging information", type=FeatureType.String),
        Feature(name="pe_debug_version", desc="Version number of the debug data format", type=FeatureType.String),
        # Codeview Features
        Feature(name="pe_debug_codeview_age", desc="Age/version number of codeview debug", type=FeatureType.Integer),
        Feature(name="pe_debug_codeview_signature", desc="Codeview type signature", type=FeatureType.String),
        Feature(
            name="pe_debug_codeview_filename", desc="PDB filepath for PE debug information", type=FeatureType.Filepath
        ),
        Feature(
            name="pe_debug_codeview_guid", desc="Codeview machine specific unique identifier", type=FeatureType.String
        ),
        # Version information features
        # Signature features
        # Load configuration features
        # Validation
        Feature(
            "authentihash",
            desc="The sha256 Authentihash associated with the file.",
            type=FeatureType.String,
        ),
        Feature(
            "signature_verification",
            desc="Verification of code signing",
            type=FeatureType.String,
        ),
        Feature(
            "signature_program_name",
            desc="Program name listed in the signature for the executable",
            type=FeatureType.String,
        ),
        Feature(
            "signature_more_info",
            desc="More info for the program provided during signing.",
            type=FeatureType.String,
        ),
        # Signer
        Feature(
            "signature_signer_name",
            desc="Subject name of signing party",
            type=FeatureType.String,
        ),
        Feature(
            "signature_signer_serial",
            desc="Certificate serial number of signer",
            type=FeatureType.String,
        ),
        Feature(
            "signature_signer_issuer",
            desc="Common name of the issuer for the singer certificate.",
            type=FeatureType.String,
        ),
        Feature(
            "signature_signer_valid_from",
            desc="Certificate valid from date for signer",
            type=FeatureType.Datetime,
        ),
        Feature(
            "signature_signer_valid_to",
            desc="Certificate valid to date for signer",
            type=FeatureType.Datetime,
        ),
        # Counter signer
        Feature(
            "signature_counter_signer_name",
            desc="Subject name of counter signing party",
            type=FeatureType.String,
        ),
        Feature(
            "signature_counter_signer_serial",
            desc="Certificate serial number of counter signer",
            type=FeatureType.String,
        ),
        Feature(
            "signature_counter_signer_issuer",
            desc="Common name of the issuer for the counter signer certificate.",
            type=FeatureType.String,
        ),
        Feature(
            "signature_counter_signer_valid_from",
            desc="Certificate valid from date for counter signer",
            type=FeatureType.Datetime,
        ),
        Feature(
            "signature_counter_signer_valid_to",
            desc="Certificate valid to date for counter signer",
            type=FeatureType.Datetime,
        ),
    ]

    def _count_features(self) -> int:
        """Count the number of features currently in self.features."""
        return sum(len(v) if isinstance(v, list) or isinstance(v, set) else 1 for v in self.features.values())

    def _cap_list_or_set_features(self, feature_names: list[str], upper_bound: int) -> None:
        """Takes a list of feature names that have list or set values and limits it to the provided upper bound."""
        for f_name in feature_names:
            inital_length = len(self.features[f_name])
            self.features[f_name] = self.features[f_name][:upper_bound]
            if len(self.features[f_name]) < inital_length:
                self.features.setdefault("tag", set()).add("lief_limited_pe_info")

    def _prioritise_features(self) -> None:
        """Drops features in priority order if there are too many feature values."""
        important_features = ["pe_resource", "pe_export_function"]
        less_important_large_features = ["pe_resource_size", "pe_resource_name", "pe_export_function_address"]

        # Only accept lists or sets in the provided features.
        important_features = [
            f_name
            for f_name in important_features
            if isinstance(self.features.get(f_name, None), list) or isinstance(self.features.get(f_name, None), set)
        ]
        less_important_large_features = [
            f_name
            for f_name in less_important_large_features
            if isinstance(self.features.get(f_name, None), list) or isinstance(self.features.get(f_name, None), set)
        ]

        # Cap everything to max feature value.
        self._cap_list_or_set_features(
            important_features + less_important_large_features, self.cfg.max_values_per_feature
        )

        # Limit all features that aren't top priority.
        count = self._count_features()
        if count > plugin_executor.MAX_FEATURE_VALUES:
            self._cap_list_or_set_features(
                less_important_large_features, self.cfg.max_values_per_less_important_feature
            )

        # Half the size of the important features
        count = self._count_features()
        if count > plugin_executor.MAX_FEATURE_VALUES:
            self._cap_list_or_set_features(
                important_features,
                max(self.cfg.max_values_per_feature // 2, self.cfg.max_values_per_less_important_feature),
            )

        # Trim the important features to the same level as the less important features.
        count = self._count_features()
        if count > plugin_executor.MAX_FEATURE_VALUES:
            self._cap_list_or_set_features(important_features, self.cfg.max_values_per_less_important_feature)

    def execute(self, job: Job):
        """Process any PE file and attempt to parse using LIEF."""
        self.features = {}
        buf = job.get_data()
        pe_file = PE.parse(buf.get_filepath())
        if not pe_file or isinstance(pe_file, lief.lief_errors):
            # if a lief error occured.
            self.features["tag"] = "pe_invalid"
        else:
            self._handle_dos(pe_file)
            self._handle_header(pe_file)
            self._handle_sections(pe_file, buf)
            self._handle_imports(pe_file)
            self._handle_exports(pe_file)
            self._handle_overlay(pe_file, buf)
            self._handle_resources(pe_file)
            self._handle_debug(pe_file)
            self._handle_signatures(pe_file)
        self._prioritise_features()
        self.add_many_feature_values(self.features)

    def _handle_dos(self, pe_file: lief.PE.Binary):
        """Parse and handle MS-DOS header and stub."""
        # unfortunately lief extracts up to PE header start which will also include the Rich Sig
        # attempt to strip that if present.. i.e. we are trying to record variation in stub
        # code/messages with this to correlate between samples.
        stub = bytes(pe_file.dos_stub)

        # return the header stub (clipped if it's longer than max length)
        self.features["pe_dos_stub"] = self._strip_rich(stub)[: self.cfg.max_value_length - 1]

    def _strip_rich(self, stub):
        """Strip any appended rich signature from the dos stub."""
        # don't used fixed 0x080 rich offset as looking for custom stubs which may not be standard size
        # 4 bytes after Rich marker is the xor key for the dynamic size list of entries
        # decode 4 byte records backwards until encounter DanS marker
        if b"Rich" not in stub:
            return stub

        idx = stub.index(b"Rich")
        # make sure we have enough buffer
        if len(stub) < idx + 8:
            return stub

        # work backwards
        key = stub[idx + 4 : idx + 8]
        i = idx - 4
        while i >= 0:
            decoded = bytes(
                (
                    stub[i] ^ key[0],
                    stub[i + 1] ^ key[1],
                    stub[i + 2] ^ key[2],
                    stub[i + 3] ^ key[3],
                )
            )
            if decoded == b"DanS":
                stub = stub[:i]
                break
            i -= 4
        return stub

    def _handle_header(self, pe_file: lief.PE.Binary):
        """Parse the PE header and optional header and set features."""
        # handle the pe file header
        header = pe_file.header
        self.features["pe_compile_time"] = datetime.utcfromtimestamp(header.time_date_stamps)
        with contextlib.suppress(Exception):
            # Will error if machine is invalid and pe_machine won't be set in this case.
            header.machine.value
            self.features["pe_machine"] = header.machine.name

        self.features["pe_characteristics"] = [c.name for c in header.characteristics_list]

        # handle the optional header
        opt_header = pe_file.optional_header

        if opt_header.magic == PE.PE_TYPE.PE32_PLUS:
            self.features.setdefault("tag", set()).add("pe32_plus")

        dll_characteristics = [c.name for c in opt_header.dll_characteristics_lists]
        image_version = "{major:d}.{minor:d}".format(
            major=opt_header.major_image_version, minor=opt_header.minor_image_version
        )
        linker_version = "{major:d}.{minor:d}".format(
            major=opt_header.major_linker_version, minor=opt_header.minor_linker_version
        )
        os_version = "{major:d}.{minor:d}".format(
            major=opt_header.major_operating_system_version, minor=opt_header.minor_operating_system_version
        )
        subsystem_version = "{major:d}.{minor:d}".format(
            major=opt_header.major_subsystem_version, minor=opt_header.minor_subsystem_version
        )

        self.features["pe_entry_point"] = opt_header.addressof_entrypoint
        self.features["pe_code_base"] = opt_header.baseof_code
        self.features["pe_checksum"] = opt_header.checksum
        self.features["pe_dll_characteristics"] = dll_characteristics
        self.features["pe_file_alignment"] = opt_header.file_alignment

        if opt_header.imagebase <= BIG_INT_MAX:
            self.features["pe_image_base"] = opt_header.imagebase
        else:
            self.features.setdefault("tag", set()).add("pe_excessive_image_base")

        if opt_header.loader_flags != 0:
            # Loader flags should be zero
            self.features.setdefault("tag", set()).add("pe_nonzero_loader_flags")

        self.features["pe_loader_flags"] = opt_header.loader_flags
        self.features["pe_image_version"] = image_version
        self.features["pe_linker_version"] = linker_version
        self.features["pe_os_version"] = os_version
        self.features["pe_subsystem_version"] = subsystem_version
        self.features["pe_num_rva_and_sizes"] = opt_header.numberof_rva_and_size
        self.features["pe_section_alignment"] = opt_header.section_alignment
        self.features["pe_code_size"] = opt_header.sizeof_code
        self.features["pe_header_size"] = opt_header.sizeof_headers

        if opt_header.sizeof_heap_commit <= BIG_INT_MAX:
            self.features["pe_heap_commit_size"] = opt_header.sizeof_heap_commit
        else:
            self.features.setdefault("tag", set()).add("pe_excessive_heap_commit")

        if opt_header.sizeof_heap_commit <= BIG_INT_MAX:
            self.features["pe_heap_reserve_size"] = opt_header.sizeof_heap_reserve
        else:
            self.features.setdefault("tag", set()).add("pe_excessive_heap_reserve")
        self.features["pe_image_size"] = opt_header.sizeof_image
        self.features["pe_init_data_size"] = opt_header.sizeof_initialized_data

        if opt_header.sizeof_stack_commit <= BIG_INT_MAX:
            self.features["pe_stack_commit_size"] = opt_header.sizeof_stack_commit
        else:
            self.features.setdefault("tag", set()).add("pe_excessive_stack_commit")

        if opt_header.sizeof_stack_reserve <= BIG_INT_MAX:
            self.features["pe_stack_reserve_size"] = opt_header.sizeof_stack_reserve
        else:
            self.features.setdefault("tag", set()).add("pe_excessive_stack_reserve")

        self.features["pe_uninit_data_size"] = opt_header.sizeof_uninitialized_data
        self.features["pe_subsystem"] = opt_header.subsystem.name

        if opt_header.win32_version_value != 0:
            # Win32 version value should be zero
            self.features.setdefault("tag", set()).add("pe_nonzero_win32_version")
        self.features["pe_win32_version"] = opt_header.win32_version_value

        if opt_header.magic != PE.PE_TYPE.PE32_PLUS and hasattr(opt_header, "baseof_data"):
            self.features["pe_data_base"] = opt_header.baseof_data

    def _handle_sections(self, pe_file: lief.PE.Binary, buf: io.BytesIO):
        """Parse sections and set features."""
        self.features["pe_section_count"] = len(pe_file.sections)

        if not pe_file.sections:
            return

        self.features["pe_section"] = []
        self.features["pe_section_virtual_size"] = []
        self.features["pe_section_virtual_address"] = []
        self.features["pe_section_raw_size"] = []
        self.features["pe_section_raw_address"] = []
        self.features["pe_section_characteristics"] = []
        self.features["pe_section_relocs_address"] = []
        self.features["pe_section_line_nums_address"] = []
        self.features["pe_section_relocs_count"] = []
        self.features["pe_section_line_nums_count"] = []
        self.features["pe_section_hash"] = []
        self.features["pe_section_raw_hash"] = []

        found_section_names = set()
        for s in pe_file.sections:
            name = s.name
            # Check if name can be decoded
            try:
                name = name.decode()
            except (UnicodeDecodeError, AttributeError):
                name = str(name).lstrip("b'").rstrip("'")

            # Ensure all duplicate sections are renamed with a leading number.
            if name in found_section_names:
                # Max sections in a file is ~1638
                for i in range(1639):
                    tmp_name = f"{i}-{name}"
                    if tmp_name not in found_section_names:
                        name = tmp_name
                        break
            found_section_names.add(name)

            self.features["pe_section"].append(FeatureValue(name, offset=s.pointerto_raw_data, size=s.sizeof_raw_data))

            # section header info
            self.features["pe_section_virtual_size"].append(FeatureValue(s.virtual_size, label=name))
            self.features["pe_section_virtual_address"].append(FeatureValue(s.virtual_address, label=name))
            self.features["pe_section_raw_size"].append(FeatureValue(s.sizeof_raw_data, label=name))
            self.features["pe_section_raw_address"].append(FeatureValue(s.pointerto_raw_data, label=name))
            self.features["pe_section_relocs_address"].append(FeatureValue(s.pointerto_relocation, label=name))
            self.features["pe_section_line_nums_address"].append(FeatureValue(s.pointerto_line_numbers, label=name))
            self.features["pe_section_relocs_count"].append(FeatureValue(s.numberof_relocations, label=name))
            self.features["pe_section_line_nums_count"].append(FeatureValue(s.numberof_line_numbers, label=name))
            self.features["pe_section_characteristics"].extend(
                [FeatureValue(c.name, label=name) for c in s.characteristics_lists]
            )

            data = bytearray(s.content)
            section_hash = md5(data).hexdigest()  # noqa: S303 # nosec B303 B324
            self.features["pe_section_hash"].append(FeatureValue(section_hash, label=name))
            buf.seek(s.pointerto_raw_data)
            raw = buf.read(s.sizeof_raw_data)
            section_hash = md5(raw).hexdigest()  # noqa: S303 # nosec B303 B324
            self.features["pe_section_raw_hash"].append(FeatureValue(section_hash, label=name))
        buf.seek(0)

    def _handle_imports(self, pe_file: lief.PE.Binary):
        """Extract import features."""
        self.features["pe_import_module_count"] = len(pe_file.imports)

        if not pe_file.imports:
            return

        self.features["pe_import_module"] = list()
        self.features["pe_import_function_count"] = list()
        self.features["pe_import_function"] = list()
        self.features["pe_import_function_ordinal"] = list()
        self.features["pe_import_function_fullname"] = list()
        self.features["pe_import_function_hint"] = list()

        fullnames = list()
        module_function_multicount = dict()

        for import_module in pe_file.imports:
            module_name = import_module.name
            self.features["pe_import_module"].append(module_name)
            self.features["pe_import_function_count"].append(
                FeatureValue(len(import_module.entries), label=module_name)
            )

            for import_function in import_module.entries:
                if import_function.is_ordinal:
                    full_name = "{module}!{ordinal:d}".format(module=module_name, ordinal=import_function.ordinal)
                    fullnames.append(full_name)

                    if full_name in self.features["pe_import_function_fullname"]:
                        module_function_multicount[full_name] += 1
                    else:
                        self.features["pe_import_function_ordinal"].append(
                            FeatureValue(import_function.ordinal, label=module_name)
                        )
                        self.features["pe_import_function_fullname"].append(full_name)
                        module_function_multicount[full_name] = 1
                else:
                    full_name = "{module}!{function}".format(module=module_name, function=import_function.name)
                    fullnames.append(full_name)

                    if full_name in self.features["pe_import_function_fullname"]:
                        module_function_multicount[full_name] += 1
                    else:
                        function_name = import_function.name
                        self.features["pe_import_function"].append(FeatureValue(function_name, label=module_name))
                        self.features["pe_import_function_fullname"].append(full_name)
                        module_function_multicount[full_name] = 1

                        self.features["pe_import_function_hint"].append(
                            FeatureValue(import_function.hint, label=full_name)
                        )

        self.features["pe_import_function_multicount"] = [
            FeatureValue(count, label=fullname) for fullname, count in module_function_multicount.items() if count > 1
        ]

        if fullnames:
            # Quarklabs' import hash includes sorting the import entries and some other minor diffs
            self.features["pe_import_hash_sorted"] = PE.get_imphash(pe_file)
            # This implementation should match pefile and what VT generate
            self.features["pe_import_hash"] = self.imphash_mandiant(pe_file)

    def imphash_mandiant(self, pe_file: lief.PE.Binary):
        """Generate importhash Mandiant way.

        Importhash logic used by Mandiant, as  described in
        https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
        and contributed to pefile project.

        This seems to be the implementation used by VT metadata.
        """
        entries = []
        for import_module in pe_file.imports:
            # lowercase
            module_name = import_module.name.lower()
            # strip extension
            if module_name.endswith((".ocx", ".sys", ".dll")):
                module_name = module_name[:-4]

            # attempt to resolve any ordinals (hope lief do same as pefile)
            import_module = PE.resolve_ordinals(import_module)
            for import_function in import_module.entries:
                if import_function.is_ordinal:
                    func_name = "ord%i" % import_function.ordinal
                else:
                    func_name = import_function.name.lower()
                # accumulate
                entries.append("%s.%s" % (module_name, func_name))

        # no sorting and use comma separator
        return md5((",".join(entries)).encode("utf-8")).hexdigest()  # noqa: S303 # nosec B303 B324

    def _handle_exports(self, pe_file: lief.PE.Binary):
        """Extract export features."""
        if not pe_file.has_exports:
            return

        export = pe_file.get_export()
        if not export.entries:
            return

        self.features["pe_export"] = export.name

        if export.export_flags != 0:
            # Export Characteristics should be zero
            self.features.setdefault("tag", set()).add("pe_nonzero_export_characteristics")
        self.features["pe_export_characteristics"] = "{:08x}".format(export.export_flags)

        self.features["pe_export_version"] = "{major:d}.{minor:d}".format(
            major=export.major_version, minor=export.minor_version
        )
        self.features["pe_export_time"] = datetime.utcfromtimestamp(export.timestamp)
        self.features["pe_export_base"] = export.ordinal_base
        self.features["pe_export_count"] = len(export.entries)

        self.features["pe_export_function"] = list()
        self.features["pe_export_function_address"] = list()
        self.features["pe_export_external_function"] = list()
        self.features["pe_export_external_function_ordinal"] = list()

        for export_function in export.entries:
            function_name = export_function.name
            if export_function.is_extern:
                self.features["pe_export_external_function"].append(function_name)
                self.features["pe_export_external_function_ordinal"].append(
                    FeatureValue(export_function.ordinal, label=function_name)
                )
            else:
                if isinstance(function_name, bytes):
                    function_name = function_name.decode(errors="backslashreplace")
                self.features["pe_export_function"].append(function_name)
                self.features["pe_export_function_address"].append(
                    FeatureValue(export_function.address, label=function_name)
                )

    def _handle_overlay(self, pe_file: lief.PE.Binary, buf: StorageProxyFile):
        """Extract binary overlay."""
        overlay_data = bytes(pe_file.overlay)
        if not overlay_data:
            return

        buf.seek(0)
        non_overlay_data = buf.read(buf.file_info.size - len(overlay_data))
        buf.seek(0)

        # If the extracted contents or it's overlay are bad don't extract them.
        if is_repeated_byte_file(overlay_data) or is_repeated_byte_file(non_overlay_data):
            return

        self.features.setdefault("tag", set()).add("pe_has_overlay")
        self.features["pe_overlay_hash"] = md5(overlay_data).hexdigest()  # noqa: S303 # nosec B303 B324
        self.features["pe_overlay_size"] = len(overlay_data)

        c = self.add_child_with_data(
            {
                "action": "extracted",
                "type": "overlay",
                "offset": "0x%0x" % len(non_overlay_data),
            },
            overlay_data,
        )
        c.add_feature_values("tag", "pe_overlay")

        c = self.add_child_with_data(
            {
                "action": "extracted",
                "type": "without overlay",
            },
            non_overlay_data,
        )
        c.add_feature_values("tag", "pe_parent_has_overlay")

    def _handle_resources(self, pe_file: lief.PE.Binary):
        """Handle resources."""
        if not pe_file.has_resources:
            return

        self.features["pe_resource"] = list()
        self.features["pe_resource_size"] = list()
        self.features["pe_resource_name"] = list()
        self.features["pe_resource_type"] = set()
        self.features["pe_resource_language"] = set()

        for res_lvl1 in pe_file.resources.childs:
            # Level One: Resource Type
            if res_lvl1.is_data:
                self.features.setdefault("tag", set()).add("pe_shallow_resource_lvl1")
                continue

            for res_lvl2 in res_lvl1.childs:
                # Level Two: Resource Identifier
                if res_lvl2.is_data:
                    self.features.setdefault("tag", set()).add("pe_shallow_resource_lvl2")
                    continue

                for res_lvl3 in res_lvl2.childs:
                    # Level Three: Language ID
                    if res_lvl3.is_directory:
                        self.features.setdefault("tag", set()).add("pe_deep_resource")
                        continue

                    # Content
                    res_content = bytes(res_lvl3.content)
                    if is_repeated_byte_file(res_content):
                        # Filter out bad files.
                        continue

                    res_hash = sha256(res_content).hexdigest()
                    res_size = len(res_content)

                    # Type
                    res_type_name = RESOURCE_TYPES(res_lvl1.id)
                    RT_PREFIX = "RT_"
                    if res_type_name is not None:
                        res_type = RT_PREFIX + res_type_name
                    else:
                        # Use the UpdateResource syntax for integer type
                        # identifiers
                        res_type = "#{type:d}".format(type=res_lvl1.id)
                        self.features.setdefault("tag", set()).add("pe_custom_resource_type")

                    # Name
                    res_name = res_lvl2.name if res_lvl2.name else str(res_lvl2.id)

                    # Language
                    lang = res_lvl3.id & 0x3FF
                    sublang = (res_lvl3.id & 0xFC00) >> 10
                    # try to imitate how VT metadata format language strings
                    res_lang = RESOURCE_LANGS(lang)
                    if res_lang is None:
                        self.features.setdefault("tag", set()).add("pe_unknown_resource_lang")
                        res_lang = "{type:d} {subtype:d}".format(type=lang, subtype=sublang)
                    else:
                        if sublang not in SUBLANG_MAP:
                            self.features.setdefault("tag", set()).add("pe_unknown_resource_sublang")
                            res_lang += " {type:d}".format(type=sublang)
                        else:
                            # looks like they try to stop lang stuttering like ENGLISH ENGLISH_US
                            sublang = get_sublang(res_lang, sublang)
                            if sublang.startswith(res_lang):
                                res_lang = sublang
                            else:
                                # but you can still get cases like 'PUNJABI' 'NEUTRAL'
                                res_lang += " " + sublang
                    # ENGLISH US vs ENGLISH_US
                    res_lang = res_lang.replace("_", " ")

                    self.features["pe_resource"].append(res_hash)
                    self.features["pe_resource_size"].append(FeatureValue(res_size, label=res_hash))
                    self.features["pe_resource_name"].append(FeatureValue(res_name, label=res_hash))
                    # keep the resource type with hash only if it's a known resource type.
                    if res_type.startswith(RT_PREFIX):
                        self.features["pe_resource_type"].add(FeatureValue(res_type, label=res_hash))
                    else:
                        self.features["pe_resource_type"].add(FeatureValue(res_type))
                    # Keep only distinct resource_languages.
                    self.features["pe_resource_language"].add(FeatureValue(res_lang))

                    # don't produce excessive numbers of children
                    if len(self.features["pe_resource"]) > self.cfg.max_resource_extraction:
                        msg = "pe_resource_extraction_limit_exceeded"
                        if msg not in self.features.get("tag", []):
                            self.features.setdefault("tag", set()).add(msg)
                        continue

                    c = self.add_child_with_data(
                        {
                            "action": "extracted",
                            "type": "resource",
                            "name": res_name,
                            "restype": res_type,
                        },
                        res_content,
                    )
                    c.add_feature_values("tag", "pe_resource")

    def _handle_debug(self, pe_file: lief.PE.Binary):
        """Extract debug details."""
        if not pe_file.has_debug:
            return

        self.features["pe_debug_type"] = []
        self.features["pe_debug_characteristics"] = []
        self.features["pe_debug_timestamp"] = []
        self.features["pe_debug_version"] = []
        self.features["pe_debug_size"] = []
        self.features["pe_debug_offset"] = []

        for debug in pe_file.debug:
            # Ignore the case where the debug.type is actually just an integer value.
            name = None if isinstance(debug.type, int) else debug.type.name
            if name is None:
                continue
            self.features["pe_debug_type"].append(
                FeatureValue(name, offset=debug.addressof_rawdata, size=debug.sizeof_data)
            )

            self.features["pe_debug_characteristics"].append(FeatureValue(debug.characteristics, label=name))
            if debug.characteristics != 0:
                self.features.setdefault("tag", set()).add("pe_nonzero_debug_characteristics")

            self.features["pe_debug_timestamp"].append(
                FeatureValue(datetime.utcfromtimestamp(debug.timestamp), label=name)
            )

            self.features["pe_debug_version"].append(
                FeatureValue(
                    "{major:d}.{minor:d}".format(major=debug.major_version, minor=debug.minor_version), label=name
                )
            )

            # still needed as separate features?
            self.features["pe_debug_size"].append(FeatureValue(debug.sizeof_data, label=name))
            self.features["pe_debug_offset"].append(FeatureValue(debug.addressof_rawdata, label=name))

            # CodeviewPDB
            if isinstance(debug, PE.CodeViewPDB):
                self.features["pe_debug_codeview_age"] = debug.age
                self.features["pe_debug_codeview_signature"] = debug.cv_signature.name
                self.features["pe_debug_codeview_filename"] = Filepath(debug.filename)
                self.features["pe_debug_codeview_guid"] = str(UUID(bytes_le=bytes(debug.signature)))

    def _handle_signatures(self, pe_file: lief.PE.Binary):
        """Extract signature features."""
        authentihash = pe_file.authentihash_sha256.hex()
        self.add_feature_values("authentihash", authentihash)

        if not pe_file.has_signatures:
            return

        def convert_int_list_to_date(date_as_list: list[int]) -> datetime | None:
            """Convert a date from a list of integers to a datetime object.

            The list of integers is in the form [YEAR, MONTH, DAY, HOUR, MINUTE, SECOND]
            """
            if len(date_as_list) != 6:
                return None
            return datetime(
                date_as_list[0],
                date_as_list[1],
                date_as_list[2],
                date_as_list[3],
                date_as_list[4],
                date_as_list[5],
                tzinfo=UTC,
            )

        def get_string(input: str | bytes) -> str:
            """Convert a union of string or bytes into a string."""
            if isinstance(input, bytes):
                with contextlib.suppress(Exception):
                    return input.decode()
                with contextlib.suppress(Exception):
                    return input.hex()
                raise Exception(f"Unable to convert a certificate byte '{input}' object to a string!")
            return input

        # Gather code signing and counter signing information.
        verification_result = pe_file.verify_signature().name
        self.add_feature_values("signature_verification", verification_result)
        sig = pe_file.signatures.__next__()
        if len(sig.signers) == 0:
            return
        signing_cert = sig.signers.__next__()
        # General issuer details
        self.add_feature_values("signature_signer_issuer", get_string(signing_cert.issuer))
        if signing_cert.cert:
            self.add_feature_values("signature_signer_name", get_string(signing_cert.cert.subject))
            self.add_feature_values(
                "signature_signer_valid_from", convert_int_list_to_date(signing_cert.cert.valid_from)
            )
            self.add_feature_values("signature_signer_valid_to", convert_int_list_to_date(signing_cert.cert.valid_to))
        if len(signing_cert.serial_number) > 0:
            self.add_feature_values("signature_signer_serial", signing_cert.serial_number.hex(":"))

        for attrib in itertools.chain(signing_cert.authenticated_attributes, signing_cert.unauthenticated_attributes):
            # Get additional information
            if isinstance(attrib, lief.PE.SpcSpOpusInfo):
                if len(attrib.program_name) > 0:
                    self.add_feature_values("signature_program_name", attrib.program_name)
                if len(attrib.more_info) > 0:
                    self.add_feature_values("signature_more_info", attrib.more_info)

            # Get counter signing information
            if isinstance(attrib, lief.PE.PKCS9CounterSignature):
                counter_signer = attrib.signer
                self.add_feature_values("signature_counter_signer_issuer", get_string(counter_signer.issuer))
                if counter_signer.cert:
                    self.add_feature_values("signature_counter_signer_name", get_string(counter_signer.cert.subject))
                    self.add_feature_values(
                        "signature_counter_signer_valid_from", convert_int_list_to_date(counter_signer.cert.valid_from)
                    )
                    self.add_feature_values(
                        "signature_counter_signer_valid_to", convert_int_list_to_date(counter_signer.cert.valid_to)
                    )
                if len(counter_signer.serial_number) > 0:
                    self.add_feature_values("signature_counter_signer_serial", counter_signer.serial_number.hex(":"))

            # Get counter signing information from alternate format.
            if isinstance(attrib, lief.PE.MsCounterSign):
                if len(attrib.certificates) == 0:
                    continue
                counter_signer_cert = attrib.certificates.__next__()
                self.add_feature_values("signature_counter_signer_issuer", get_string(counter_signer_cert.issuer))
                self.add_feature_values("signature_counter_signer_name", get_string(counter_signer_cert.subject))
                self.add_feature_values(
                    "signature_counter_signer_valid_from", convert_int_list_to_date(counter_signer_cert.valid_from)
                )
                self.add_feature_values(
                    "signature_counter_signer_valid_to", convert_int_list_to_date(counter_signer_cert.valid_to)
                )
                if len(counter_signer_cert.serial_number) > 0:
                    self.add_feature_values(
                        "signature_counter_signer_serial", counter_signer_cert.serial_number.hex(":")
                    )


# Lief sublang mappings aren't mapping correctly, using these mappings instead
# courtesy of https://github.com/erocarrera/pefile:
SUBLANG_TUPLES = [
    ("NEUTRAL", 0x00),
    ("DEFAULT", 0x01),
    ("SYS_DEFAULT", 0x02),
    ("ARABIC_SAUDI_ARABIA", 0x01),
    ("ARABIC_IRAQ", 0x02),
    ("ARABIC_EGYPT", 0x03),
    ("ARABIC_LIBYA", 0x04),
    ("ARABIC_ALGERIA", 0x05),
    ("ARABIC_MOROCCO", 0x06),
    ("ARABIC_TUNISIA", 0x07),
    ("ARABIC_OMAN", 0x08),
    ("ARABIC_YEMEN", 0x09),
    ("ARABIC_SYRIA", 0x0A),
    ("ARABIC_JORDAN", 0x0B),
    ("ARABIC_LEBANON", 0x0C),
    ("ARABIC_KUWAIT", 0x0D),
    ("ARABIC_UAE", 0x0E),
    ("ARABIC_BAHRAIN", 0x0F),
    ("ARABIC_QATAR", 0x10),
    ("AZERI_LATIN", 0x01),
    ("AZERI_CYRILLIC", 0x02),
    ("CHINESE_TRADITIONAL", 0x01),
    ("CHINESE_SIMPLIFIED", 0x02),
    ("CHINESE_HONGKONG", 0x03),
    ("CHINESE_SINGAPORE", 0x04),
    ("CHINESE_MACAU", 0x05),
    ("DUTCH", 0x01),
    ("DUTCH_BELGIAN", 0x02),
    ("ENGLISH_US", 0x01),
    ("ENGLISH_UK", 0x02),
    ("ENGLISH_AUS", 0x03),
    ("ENGLISH_CAN", 0x04),
    ("ENGLISH_NZ", 0x05),
    ("ENGLISH_EIRE", 0x06),
    ("ENGLISH_SOUTH_AFRICA", 0x07),
    ("ENGLISH_JAMAICA", 0x08),
    ("ENGLISH_CARIBBEAN", 0x09),
    ("ENGLISH_BELIZE", 0x0A),
    ("ENGLISH_TRINIDAD", 0x0B),
    ("ENGLISH_ZIMBABWE", 0x0C),
    ("ENGLISH_PHILIPPINES", 0x0D),
    ("FRENCH", 0x01),
    ("FRENCH_BELGIAN", 0x02),
    ("FRENCH_CANADIAN", 0x03),
    ("FRENCH_SWISS", 0x04),
    ("FRENCH_LUXEMBOURG", 0x05),
    ("FRENCH_MONACO", 0x06),
    ("GERMAN", 0x01),
    ("GERMAN_SWISS", 0x02),
    ("GERMAN_AUSTRIAN", 0x03),
    ("GERMAN_LUXEMBOURG", 0x04),
    ("GERMAN_LIECHTENSTEIN", 0x05),
    ("ITALIAN", 0x01),
    ("ITALIAN_SWISS", 0x02),
    ("KASHMIRI_SASIA", 0x02),
    ("KASHMIRI_INDIA", 0x02),
    ("KOREAN", 0x01),
    ("LITHUANIAN", 0x01),
    ("MALAY_MALAYSIA", 0x01),
    ("MALAY_BRUNEI_DARUSSALAM", 0x02),
    ("NEPALI_INDIA", 0x02),
    ("NORWEGIAN_BOKMAL", 0x01),
    ("NORWEGIAN_NYNORSK", 0x02),
    ("PORTUGUESE", 0x02),
    ("PORTUGUESE_BRAZILIAN", 0x01),
    ("SERBIAN_LATIN", 0x02),
    ("SERBIAN_CYRILLIC", 0x03),
    ("SPANISH", 0x01),
    ("SPANISH_MEXICAN", 0x02),
    ("SPANISH_MODERN", 0x03),
    ("SPANISH_GUATEMALA", 0x04),
    ("SPANISH_COSTA_RICA", 0x05),
    ("SPANISH_PANAMA", 0x06),
    ("SPANISH_DOMINICAN_REPUBLIC", 0x07),
    ("SPANISH_VENEZUELA", 0x08),
    ("SPANISH_COLOMBIA", 0x09),
    ("SPANISH_PERU", 0x0A),
    ("SPANISH_ARGENTINA", 0x0B),
    ("SPANISH_ECUADOR", 0x0C),
    ("SPANISH_CHILE", 0x0D),
    ("SPANISH_URUGUAY", 0x0E),
    ("SPANISH_PARAGUAY", 0x0F),
    ("SPANISH_BOLIVIA", 0x10),
    ("SPANISH_EL_SALVADOR", 0x11),
    ("SPANISH_HONDURAS", 0x12),
    ("SPANISH_NICARAGUA", 0x13),
    ("SPANISH_PUERTO_RICO", 0x14),
    ("SWEDISH", 0x01),
    ("SWEDISH_FINLAND", 0x02),
    ("URDU_PAKISTAN", 0x01),
    ("URDU_INDIA", 0x02),
    ("UZBEK_LATIN", 0x01),
    ("UZBEK_CYRILLIC", 0x02),
    ("DUTCH_SURINAM", 0x03),
    ("ROMANIAN", 0x01),
    ("ROMANIAN_MOLDAVIA", 0x02),
    ("RUSSIAN", 0x01),
    ("RUSSIAN_MOLDAVIA", 0x02),
    ("CROATIAN", 0x01),
    ("LITHUANIAN_CLASSIC", 0x02),
    ("GAELIC", 0x01),
    ("GAELIC_SCOTTISH", 0x02),
    ("GAELIC_MANX", 0x03),
]

SUBLANG_MAP = {}
for k, v in SUBLANG_TUPLES:
    SUBLANG_MAP.setdefault(v, []).append(k)


def get_sublang(lang_name, sublang_id):
    """Retrieve sub language for language/id."""
    # let it raise KeyError
    sublangs = SUBLANG_MAP[sublang_id]
    # find lang specific entry
    for lang in sublangs:
        if lang_name in lang:
            return lang
    # fallback to first 'default' entry
    return sublangs[0]


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginLiefPE)


if __name__ == "__main__":
    main()
