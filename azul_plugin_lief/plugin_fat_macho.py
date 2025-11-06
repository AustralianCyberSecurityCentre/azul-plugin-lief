"""Unpack FAT Mach-O files.

This plugin parses fat Mach-O files and extracts the fit Mach-O's as children.
Doesn't actually make use of LIEF but co-located for convenience with other
Mach-O plugin/s.
"""

from binascii import b2a_hex

from azul_runner import (
    BinaryPlugin,
    DataLabel,
    Feature,
    FeatureType,
    FeatureValue,
    Job,
    State,
    add_settings,
    cmdline_run,
)

from . import fat_macho


class AzulPluginFatMachO(BinaryPlugin):
    """Unpack FAT Mach-O files."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.04.08"
    SETTINGS = add_settings(
        filter_data_types={DataLabel.CONTENT: ["executable/mach-o"]},
    )
    FEATURES = [
        Feature(name="tag", desc="Any informational label about the binary", type=FeatureType.String),
        Feature(name="fat_macho_magic", desc="Magic value of Mach-O indicating endianess", type=FeatureType.String),
        Feature(
            name="fat_macho_binary_count", desc="Number of binaries contained in the Mach-O", type=FeatureType.Integer
        ),
        Feature(name="fat_macho_binary_offset", desc="Offset of the contained binary", type=FeatureType.Integer),
        Feature(
            name="fat_macho_binary_cpu_type", desc="CPU type targeted by the contained binary", type=FeatureType.String
        ),
        Feature(
            name="fat_macho_binary_cpu_subtype",
            desc="CPU subtype targeted by the contained binary",
            type=FeatureType.String,
        ),
        Feature(
            name="fat_macho_binary_cpu_subtype_flag",
            desc="Flag set in CPU subtype definition",
            type=FeatureType.String,
        ),
        Feature(name="fat_macho_binary_size", desc="Size of the contained binary", type=FeatureType.Integer),
        Feature(name="fat_macho_binary_alignment", desc="Alignment of the contained binary", type=FeatureType.Integer),
    ]

    def execute(self, job: Job):
        """Process any Mach-O file and if fat type, extract the contained binaries as children."""
        data = job.get_data().read()
        try:
            header = fat_macho.unpack(data)
        except fat_macho.BadMagicError:
            # Not a fat Mach-O
            return State(State.Label.OPT_OUT)
        except ValueError:
            # One of the enum's was unknown
            self.add_feature_values("tag", "fat_macho_bad_arch")
            return
        except IndexError:
            # Not enough data
            self.add_feature_values("tag", "macho_missing_data")
            return

        features = {}

        # set basic features
        features["fat_macho_magic"] = b2a_hex(header[0].magic.value).decode("utf-8")
        features["fat_macho_binary_count"] = header[0].nfat_arch

        # extract children and their details
        fat_macho_binary_offset = list()
        fat_macho_binary_cpu_type = list()
        fat_macho_binary_cpu_subtype = list()
        fat_macho_binary_cpu_subtype_flag = list()
        fat_macho_binary_size = list()
        fat_macho_binary_alignment = list()
        tags = list()
        data_outside = zero_data = False
        for arch in header[1]:
            label = str(arch.offset)
            fat_macho_binary_offset.append(arch.offset)
            fat_macho_binary_cpu_type.append(FeatureValue(arch.cputype.name, label=label))
            fat_macho_binary_cpu_subtype.append(FeatureValue(arch.cpusubtype.name, label=label))
            if arch.flags and arch.flags.value:
                fat_macho_binary_cpu_subtype_flag.append(FeatureValue(arch.flags.name, label=label))
            fat_macho_binary_size.append(FeatureValue(arch.size, label=label))
            fat_macho_binary_alignment.append(FeatureValue(arch.align, label=label))

            if arch.size == 0:
                zero_data = True
                continue
            if arch.offset > len(data) or arch.offset + arch.size > len(data):
                data_outside = True
                continue

            child_features = dict(tag="contained_in_fat_macho")
            c = self.add_child_with_data(
                {
                    "action": "extracted",
                    "offset": "0x%0x" % arch.offset,
                    "cpu_type": arch.cputype.name,
                    "cpu_subtype": arch.cpusubtype.name,
                },
                data[arch.offset : arch.offset + arch.size],
            )
            c.add_many_feature_values(child_features)

        # handle the case where a child may not exist in the fat Mach-O
        if data_outside:
            tags.append("fat_macho_invalid_pointer")
        # handle the case where a child may have zero data
        if zero_data:
            tags.append("fat_macho_empty_arch")

        features["fat_macho_binary_offset"] = fat_macho_binary_offset
        features["fat_macho_binary_cpu_type"] = fat_macho_binary_cpu_type
        features["fat_macho_binary_cpu_subtype"] = fat_macho_binary_cpu_subtype
        features["fat_macho_binary_cpu_subtype_flag"] = fat_macho_binary_cpu_subtype_flag
        features["fat_macho_binary_size"] = fat_macho_binary_size
        features["fat_macho_binary_alignment"] = fat_macho_binary_alignment
        features["tag"] = tags
        self.add_many_feature_values(features)


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginFatMachO)


if __name__ == "__main__":
    main()
