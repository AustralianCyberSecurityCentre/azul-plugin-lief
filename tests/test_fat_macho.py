"""
FAT Mach-O test suite
=====================

Test the FAT Mach-O plugin

"""

from azul_runner import (
    FV,
    DataLabel,
    Event,
    EventData,
    EventParent,
    Filepath,
    JobResult,
    State,
    Uri,
    test_template,
)

from azul_plugin_lief.plugin_fat_macho import AzulPluginFatMachO


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginFatMachO

    def test_fat_macho_slim(self):
        """Test FAT Mach-O plugin on non fat binary"""
        result = self.do_execution(
            data_in=[
                (
                    DataLabel.CONTENT,
                    self.load_test_file_bytes(
                        "65f2789cd6c346f590ad6161621f9dd66e1b0096e32be07c058fed511f9d3ce9",
                        "VLC for ios thin.",
                    ),
                )
            ]
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT)))

    def test_macho_fat(self):
        """Test FAT Mach-O plugin with 3 archs"""
        result = self.do_execution(
            data_in=[
                (
                    DataLabel.CONTENT,
                    self.load_test_file_bytes(
                        "67b54e142d22b5a860f8a371bf49339a934bd233ffce16ff54a182c8c78f8dfb",
                        "Benign fat lib swift darwin.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="67b54e142d22b5a860f8a371bf49339a934bd233ffce16ff54a182c8c78f8dfb",
                        features={
                            "fat_macho_binary_alignment": [
                                FV(14, label="114688"),
                                FV(14, label="16384"),
                                FV(14, label="212992"),
                            ],
                            "fat_macho_binary_count": [FV(3)],
                            "fat_macho_binary_cpu_subtype": [
                                FV("ARM64_ALL", label="212992"),
                                FV("ARM_V7", label="16384"),
                                FV("ARM_V7S", label="114688"),
                            ],
                            "fat_macho_binary_cpu_type": [
                                FV("ARM", label="114688"),
                                FV("ARM", label="16384"),
                                FV("ARM64", label="212992"),
                            ],
                            "fat_macho_binary_offset": [FV(16384), FV(114688), FV(212992)],
                            "fat_macho_binary_size": [
                                FV(89344, label="114688"),
                                FV(89344, label="16384"),
                                FV(90480, label="212992"),
                            ],
                            "fat_macho_magic": [FV("cafebabe")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="67b54e142d22b5a860f8a371bf49339a934bd233ffce16ff54a182c8c78f8dfb",
                        ),
                        entity_type="binary",
                        entity_id="09ff8eeda4693f9146e6a5efcb5ddd5c70686a3bcedd3defdfec11c03f6b352a",
                        relationship={
                            "action": "extracted",
                            "offset": "0x4000",
                            "cpu_type": "ARM",
                            "cpu_subtype": "ARM_V7",
                        },
                        data=[
                            EventData(
                                hash="09ff8eeda4693f9146e6a5efcb5ddd5c70686a3bcedd3defdfec11c03f6b352a",
                                label=DataLabel.CONTENT,
                            )
                        ],
                        features={"tag": [FV("contained_in_fat_macho")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="67b54e142d22b5a860f8a371bf49339a934bd233ffce16ff54a182c8c78f8dfb",
                        ),
                        entity_type="binary",
                        entity_id="ed53fd308f8997c8437a664dcff4dcf2cae9c54e6fc1e208bdb6aa56d065d4d3",
                        relationship={
                            "action": "extracted",
                            "offset": "0x1c000",
                            "cpu_type": "ARM",
                            "cpu_subtype": "ARM_V7S",
                        },
                        data=[
                            EventData(
                                hash="ed53fd308f8997c8437a664dcff4dcf2cae9c54e6fc1e208bdb6aa56d065d4d3",
                                label=DataLabel.CONTENT,
                            )
                        ],
                        features={"tag": [FV("contained_in_fat_macho")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="67b54e142d22b5a860f8a371bf49339a934bd233ffce16ff54a182c8c78f8dfb",
                        ),
                        entity_type="binary",
                        entity_id="a9aa12e8d9cc5bc3af94ec4c2353ddd93f396fc14cf665a99abfb91dd4f9a371",
                        relationship={
                            "action": "extracted",
                            "offset": "0x34000",
                            "cpu_type": "ARM64",
                            "cpu_subtype": "ARM64_ALL",
                        },
                        data=[
                            EventData(
                                hash="a9aa12e8d9cc5bc3af94ec4c2353ddd93f396fc14cf665a99abfb91dd4f9a371",
                                label=DataLabel.CONTENT,
                            )
                        ],
                        features={"tag": [FV("contained_in_fat_macho")]},
                    ),
                ],
                data={
                    "09ff8eeda4693f9146e6a5efcb5ddd5c70686a3bcedd3defdfec11c03f6b352a": b"",
                    "ed53fd308f8997c8437a664dcff4dcf2cae9c54e6fc1e208bdb6aa56d065d4d3": b"",
                    "a9aa12e8d9cc5bc3af94ec4c2353ddd93f396fc14cf665a99abfb91dd4f9a371": b"",
                },
            ),
        )
