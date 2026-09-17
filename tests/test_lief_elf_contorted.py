"""
LIEF ELF contorted test suite.

Test the elf plugin with binaries with uncommon edge cases
"""

from azul_runner import FV, DataLabel, Event, JobResult, State, test_template

from azul_plugin_lief.lief_elf import LiefELF

import lief
from lief import ELF, Binary
from lief.ELF import parse
from pwn import context
from pwnlib import shellcraft
from pwnlib.asm import make_elf_from_assembly


MAX_FEATURE_VALUES = 1000
MAX_VALUE_LENGTH = 4000


def add_section(
    binary: Binary,
    name: str,
    type: ELF.Section.TYPE,
    content: list[int] | None,
    virtual_address: int,
    flags: int,
):
    section = lief.ELF.Section(name)
    if content:
        section.content = content
    section.type = type
    section.virtual_address = virtual_address
    section.flags = flags
    # Make them unloaded sections so we can add as many as we want
    binary.add(section, loaded=False)  # type: ignore


def generate_stager():
    """Use pwntools to generate a stager binary.

    requires 'build-essential' installed on system.

    Using the generated, valid, ELF binary as a base, we can then use Lief to manipulate it
    to test ourselves with uncommon or absurd edge cases.
    """
    context.clear()
    context.arch = "amd64"

    sc = shellcraft.amd64.linux.connectstager("localhost", 9999)  # type: ignore
    filename = make_elf_from_assembly(sc)
    return filename


class TestExecute(test_template.TestPlugin):
    """Tests to check handling of intentionally manipulated ELFs."""

    PLUGIN_TO_TEST = LiefELF
    STAGER = generate_stager()

    def test_lief_elf_patchelf_detection(self):
        """Tests on an ELF file that is suspected to have had patchelf ran on it.

        Patchelf can overwrite a section with 'X's. Instead of lifting the X's, we tag the binary
        with the elf_note_patchelf feature.

        VT binaries we suspect that have been patchelf (or at least have same artifacts in them)
        3027ee7a51900e14937202b0c1dfea85f8129e273b8a732d8e83cba471c1eba2
        83d09b9ff0f06208fae4295a84dd91cb7637a4259f1ccf1fc8b94eedc858d8dc
        2b8a4ddd9d7b3c5efe4541d6d3fad4fa94dbe8b9e57ea3964cccfcc62f0d75e2
        414c6681b905ffc86c956caf340fc384fc2af50b6b94b659709f314c35efb2f6
        36c673da9f1acfcd1a1f169a613c7a38a580dfae17d619a9ce48ee5640f311fa
        dad38f6598496700c33c1be80de86c45298c79e17010b110a22f19ddc9f7d231
        972ba74b963a2355e8244eb9656d3a082e9954935a068291eff739460f9a4423
        """
        result = self.do_execution(
            data_in=[
                (
                    DataLabel.CONTENT,
                    self.load_test_file_bytes(
                        "414c6681b905ffc86c956caf340fc384fc2af50b6b94b659709f314c35efb2f6",
                        "binary containing artifacts from being patchelf'd",
                    ),
                )
            ],
            verify_input_content=False,
        )
        self.assertIn("elf_note_patchelf", result.events[0].features)

    def test_lief_elf_mangled_names(self):
        """Tests on an ELF file that contains symbols that the names do not de-mangle nicely.

        Just confirm we handle them and mark malformed. This should allow us to come back later and
        have all the binaries that have strange or unhandled outputs marked for further investigation
        """

        result = self.do_execution(
            data_in=[
                (
                    DataLabel.CONTENT,
                    self.load_test_file_bytes(
                        "d2f7f8d9c4d2e3d1e83e1a69d27f6296536746497a883d08567fe4248ee856d0",
                        "binary containing symbols whose names do not de-mangle nicely",
                    ),
                )
            ],
            verify_input_content=False,
        )
        # job result output is massive. Just check that we caught all the malformed values
        self.assertIn("malformed", result.events[0].features)
        caught_malformed = result.events[0].features["malformed"]

        expected = str(
            [
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 12265]: std::tuple_element<0ul, std::tuple<std::map<std::_"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 4094]: std::unique_ptr<std::map<std::__cxx11::basic_strin"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 4550]: std::_Rb_tree_node<std::pair<std::__cxx11::basic_s"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 5906]: std::map<std::__cxx11::basic_string<char, std::cha"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 6688]: std::_Head_base<1ul, nlohmann::basic_json<std::map"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 6796]: std::vector<nlohmann::basic_json<std::map, std::ve"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 7365]: std::_Tuple_impl<0ul, std::vector<nlohmann::basic_"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 7711]: std::tuple_element<1ul, std::tuple<std::map<std::_"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 8190]: std::_Tuple_impl<0ul, std::map<std::__cxx11::basic"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 8788]: std::__uniq_ptr_data<std::vector<nlohmann::basic_j"
                ),
                FV(
                    "Feature value too long (elf_export) [ACTUAL SIZE: 9693]: std::_Tuple_impl<0ul, std::map<std::__cxx11::basic"
                ),
            ]
        )
        self.assertEqual(str(caught_malformed), expected)
        self.assertEqual(
            result.state,
            State(State.Label.COMPLETED_WITH_ERRORS, message="Malformed features found"),
        )

    def test_lief_elf_invalid_unicode_section_name(self):
        """Tests on an ELF file that contains a section with an invalid unicode section names.

        Takes the stager and changes section name to invalid unicode
        """
        binary = parse(self.STAGER)
        self.assertIsNotNone(binary)
        assert binary is not None
        section = binary.get_section(".shellcode")
        self.assertIsNotNone(section)
        assert section is not None
        section.name = b"\x80"  # type: ignore

        result = self.do_execution(
            data_in=[
                (
                    DataLabel.CONTENT,
                    binary.write_to_bytes(),
                )
            ],
            verify_input_content=False,
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="2f93b8546ec8b24a58fbfd66ce2b85d975093d111ab9b20dc3f1f8aa36f72346",
                        features={
                            "elf_abi_version": [FV("0")],
                            "elf_class": [FV("ELF64")],
                            "elf_data": [FV("2's complement, little endian")],
                            "elf_entrypoint": [FV("268435456")],
                            "elf_hdr_version": [FV("1 (current)")],
                            "elf_header_size": [FV("64")],
                            "elf_machine": [FV("Advanced Micro Devices X86-64")],
                            "elf_num_prog_headers": [FV("3")],
                            "elf_num_section_headers": [FV("5")],
                            "elf_obj_version": [FV("0x1")],
                            "elf_os_abi": [FV("UNIX - System V")],
                            "elf_processor_flag": [FV("0")],
                            "elf_program_header_offset": [FV("64")],
                            "elf_program_header_size": [FV("56")],
                            "elf_section": [
                                FV("", offset=0, size=0),
                                FV(".shstrtab", offset=4535, size=29),
                                FV(".strtab", offset=4464, size=71),
                                FV(".symtab", offset=4224, size=240),
                                FV("\\x80", offset=4096, size=122),
                            ],
                            "elf_section_alignment": [
                                FV("0", label=""),
                                FV("1", label=".shstrtab"),
                                FV("1", label=".strtab"),
                                FV("1", label="\\x80"),
                                FV("8", label=".symtab"),
                            ],
                            "elf_section_entropy": [
                                FV("0.0", label=""),
                                FV("1.261128138866488", label=".symtab"),
                                FV("3.2206036345977784", label=".shstrtab"),
                                FV("3.8481720608831615", label=".strtab"),
                                FV("4.961172843706018", label="\\x80"),
                            ],
                            "elf_section_entry_size": [
                                FV("0", label=""),
                                FV("0", label=".shstrtab"),
                                FV("0", label=".strtab"),
                                FV("0", label="\\x80"),
                                FV("24", label=".symtab"),
                            ],
                            "elf_section_flags": [
                                FV("", label=""),
                                FV("", label=".shstrtab"),
                                FV("", label=".strtab"),
                                FV("", label=".symtab"),
                                FV("WAX", label="\\x80"),
                            ],
                            "elf_section_hash": [
                                FV("111a2ea8f864abed4a626a6b2caabacf1062165327d0ceaea3c7cad207a8401e", label="\\x80"),
                                FV(
                                    "3eca9174fdc1858f93119dc3cd0d98897948d17c373de4cb58cfbdc9eefdeb74", label=".strtab"
                                ),
                                FV(
                                    "acf0c1f17fa189bd1b4bd0a4766474743b93a21d4f7ad367b0e7e6fe638b8df9",
                                    label=".shstrtab",
                                ),
                                FV(
                                    "d461e4c172d3a0eb77fc1bd78013401f30e30e7ec9213c212c65f0158bc08298", label=".symtab"
                                ),
                                FV("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", label=""),
                            ],
                            "elf_section_header_offset": [FV("4576")],
                            "elf_section_header_size": [FV("64")],
                            "elf_section_information": [
                                FV("0", label=""),
                                FV("0", label=".shstrtab"),
                                FV("0", label=".strtab"),
                                FV("0", label="\\x80"),
                                FV("10", label=".symtab"),
                            ],
                            "elf_section_link": [
                                FV("0", label=""),
                                FV("0", label=".shstrtab"),
                                FV("0", label=".strtab"),
                                FV("0", label="\\x80"),
                                FV("3", label=".symtab"),
                            ],
                            "elf_section_name_table_idx": [FV("4")],
                            "elf_section_num_flags": [
                                FV("0", label=""),
                                FV("0", label=".shstrtab"),
                                FV("0", label=".strtab"),
                                FV("0", label=".symtab"),
                                FV("7", label="\\x80"),
                            ],
                            "elf_section_segments": [
                                FV("", label=""),
                                FV("", label=".shstrtab"),
                                FV("", label=".strtab"),
                                FV("", label=".symtab"),
                                FV("LOAD", label="\\x80"),
                            ],
                            "elf_section_type": [
                                FV("NULL", label=""),
                                FV("PROGBITS", label="\\x80"),
                                FV("STRTAB", label=".shstrtab"),
                                FV("STRTAB", label=".strtab"),
                                FV("SYMTAB", label=".symtab"),
                            ],
                            "elf_section_virtual_address": [
                                FV("0", label=""),
                                FV("0", label=".shstrtab"),
                                FV("0", label=".strtab"),
                                FV("0", label=".symtab"),
                                FV("268435456", label="\\x80"),
                            ],
                            "elf_segment": [
                                FV("0", offset=0, size=232),
                                FV("1", offset=4096, size=122),
                                FV("2", offset=0, size=0),
                            ],
                            "elf_segment_alignment": [
                                FV("16", label="2"),
                                FV("4096", label="0"),
                                FV("4096", label="1"),
                            ],
                            "elf_segment_flags": [FV("R--", label="0"), FV("RWX", label="1"), FV("RWX", label="2")],
                            "elf_segment_physical_address": [
                                FV("0", label="2"),
                                FV("268431360", label="0"),
                                FV("268435456", label="1"),
                            ],
                            "elf_segment_sections": [FV("", label="0"), FV("", label="2"), FV("b'\\x80'", label="1")],
                            "elf_segment_type": [
                                FV("GNU_STACK", label="2"),
                                FV("LOAD", label="0"),
                                FV("LOAD", label="1"),
                            ],
                            "elf_segment_virtual_address": [
                                FV("0", label="2"),
                                FV("268431360", label="0"),
                                FV("268435456", label="1"),
                            ],
                            "elf_segment_virtual_size": [
                                FV("0", label="2"),
                                FV("122", label="1"),
                                FV("232", label="0"),
                            ],
                            "elf_type": [FV("EXEC (Executable file)")],
                        },
                    )
                ],
            ),
        )

    def test_lief_elf_to_many_sections(self):
        """Tests on an ELF file that contains a huge number of sections.

        Goal is just to ensure we don't throw un-caught exceptions and properly mark we are
        malformed.
        """
        binary = parse(self.STAGER)
        self.assertIsNotNone(binary)
        assert binary is not None
        upside_down_smile = 0x1F643
        for i in range(MAX_FEATURE_VALUES):
            add_section(binary, (chr(upside_down_smile + i)), lief.ELF.Section.TYPE.NOTE, None, 0, 0)
        result = self.do_execution(
            data_in=[
                (
                    DataLabel.CONTENT,
                    binary.write_to_bytes(),
                )
            ],
            verify_input_content=False,
        )
        self.assertEqual(
            result.state,
            State(
                State.Label.COMPLETED_WITH_ERRORS,
                message="Partial completion occurred with the following errors: too many values for feature elf_section (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_alignment (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_entropy (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_entry_size (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_flags (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_hash (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_information (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_link (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_num_flags (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_segments (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_type (1005) capping returned values to values at 1000\ntoo many values for feature elf_section_virtual_address (1005) capping returned values to values at 1000\ntoo many values for plugin (12042) only returning first (9500 values)\ndropping 1000/1000 values from elf_section_virtual_address\ndropping 1000/1000 values from elf_section_type\ndropping 542/1000 values from elf_section_segments",
            ),
        )

    def test_lief_elf_large_section_name(self):
        """Tests on an ELF file that contains a section with a very long name.

        Want to ensure we don't error and we elevate malformed value.
        """
        binary = parse(self.STAGER)
        self.assertIsNotNone(binary)
        assert binary is not None
        section = binary.get_section(".shellcode")
        self.assertIsNotNone(section)
        assert section is not None
        section.name = "C" * (MAX_VALUE_LENGTH + 1000)

        result = self.do_execution(
            data_in=[
                (
                    DataLabel.CONTENT,
                    binary.write_to_bytes(),
                )
            ],
            verify_input_content=False,
        )
        expected = str(
            [
                FV(
                    f"Feature value too long (elf_section) [ACTUAL SIZE: {MAX_VALUE_LENGTH + 1000}]: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
                )
            ]
        )

        self.assertIn("malformed", result.events[0].features)
        caught_malformed = result.events[0].features["malformed"]
        self.assertEqual(str(caught_malformed), expected)
