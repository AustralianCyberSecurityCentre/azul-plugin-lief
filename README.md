# Azul Plugin Lief

Plugins for featuring metadata and extracting resources from executable formats.
Utilises the Quarkslab project [LIEF](https://lief.quarkslab.com).

Currently Supports:

- Microsoft Portable Executables
- Mach-O Executables (including FAT Mach-O extraction)
- ELF (Executable and Linkable Format) files

## Development Installation

To install azul-plugin-lief for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage: azul-lief-pe

Parses Microsoft Portable Executables.

Features available executable metadata, including:

- Header Fields
- Imports/Exports
- Sections
- Resources
- Debug Information

Any resources and overlay are extracted as child entities.

Usage on local files:

```
azul-lief-pe test.exe
```

Example Output:

```
----- LiefPe results -----
OK

Output features:
                pe_import_hash: 664dd7e57d262f7f4a5d7b2460013b83
                pe_export_time: 2000-10-21 08:32:26
               pe_loader_flags: 0
          pe_subsystem_version: 4.0
               pe_debug_offset: 61828
            pe_characteristics: CHARA_32BIT_MACHINE
                                DLL
                                EXECUTABLE_IMAGE
                                LINE_NUMS_STRIPPED
                                LOCAL_SYMS_STRIPPED
       pe_section_virtual_size: .reloc - 26008
                                .data - 60928
                                .rsrc - 468136
                                .text - 515979
             pe_file_alignment: 512
            pe_export_function: D3DIndexBuffer8GetData
                                D3DIndexBuffer8SetData
                                D3DVertexBuffer8GetData
                                D3DVertexBuffer8SetData
                                D3DXMeshIndexBuffer8GetData
                                D3DXMeshIndexBuffer8SetData
                                D3DXMeshVertexBuffer8GetData
                                D3DXMeshVertexBuffer8SetData
                                DXCopyMemory
                                DXLockArray8
                                DXUnlockArray8
                                DllCanUnloadNow
                                DllGetClassObject
                                ...
     pe_section_relocs_address: .data - 0
                                .reloc - 0
                                .rsrc - 0
                                .text - 0
     pe_export_characteristics: 00000000
   pe_import_function_fullname: ADVAPI32.dll!RegCloseKey
                                ADVAPI32.dll!RegCreateKeyExA
                                ADVAPI32.dll!RegDeleteKeyA
                                ADVAPI32.dll!RegEnumKeyExA
                                ADVAPI32.dll!RegOpenKeyA
                                ADVAPI32.dll!RegOpenKeyExA
                                ADVAPI32.dll!RegQueryValueExA
                                ADVAPI32.dll!RegSetValueExA
                                GDI32.dll!CreateCompatibleDC
                                GDI32.dll!CreateDIBSection
                                GDI32.dll!CreateFontIndirectA
                                GDI32.dll!CreateICA
                                ...
                 pe_os_version: 5.1
              pe_section_count: 4
    pe_section_line_nums_count: .data - 0
                                .reloc - 0
                                .rsrc - 0
                                .text - 0
              pe_import_module: ADVAPI32.dll
                                GDI32.dll
                                KERNEL32.dll
                                MSACM32.dll
                                MSVCRT.dll
                                OLEAUT32.dll
                                USER32.dll
                                d3dxof.dll
                                ole32.dll
        pe_import_module_count: 9
  pe_section_line_nums_address: .data - 0
                                .reloc - 0
                                .rsrc - 0
                                .text - 0
                pe_entry_point: 62086
                  pe_data_base: 520192
          pe_num_rva_and_sizes: 16
    pe_export_function_ordinal: VB_D3DXVec2Dot - 5
                                VB_D3DXVec2CCW - 6
                                VB_D3DXVec2Add - 7
                                VB_D3DXVec2Subtract - 8
                                VB_D3DXVec2Minimize - 9
                                VB_D3DXVec2Maximize - 10
                                VB_D3DXVec2Scale - 11
                                VB_D3DXVec2Lerp - 12
                                VB_D3DXVec2Normalize - 13
                                VB_D3DXVec2Hermite - 14
                                ...
                  pe_code_base: 4096
                pe_export_base: 5
    pe_import_function_ordinal: OLEAUT32.dll - 2
                                OLEAUT32.dll - 6
                                OLEAUT32.dll - 15
                                OLEAUT32.dll - 16
                                OLEAUT32.dll - 161
                                OLEAUT32.dll - 163
              pe_resource_size: 230f76986b2ecdd5b30cb86e5782bbc553592c33fb2d455185ac744b649a9d95 - 27
                                d05302600e4da5ed9c8cf153af840fbacb4cf5816ff92d0b00e3fd0c79f366a6 - 124
                                422a899d71fead1ea92c9e1695a60a96c4ae69c642052e5c6145bb5df560602d - 876
                                c3602f46f15965449c3da5f81f3e393aa964ee5e3d82ffe68c5b290767dfc81b - 466744
                  pe_code_size: 516096
               pe_export_count: 139
      pe_debug_characteristics: 0
                     pe_export: DX8VB.DLL
    pe_section_characteristics: .text - CNT_CODE
                                .data - CNT_INITIALIZED_DATA
                                .reloc - CNT_INITIALIZED_DATA
                                .rsrc - CNT_INITIALIZED_DATA
                                .reloc - MEM_DISCARDABLE
                                .text - MEM_EXECUTE
                                .data - MEM_READ
                                .reloc - MEM_READ
                                .rsrc - MEM_READ
                                .text - MEM_READ
                                .data - MEM_WRITE
             pe_export_version: 0.0
                 pe_debug_size: 81
                    pe_section: .data
                                .reloc
                                .rsrc
                                .text
           pe_heap_commit_size: 4096
                   pe_checksum: 1069756
              pe_win32_version: 0
               pe_section_hash: .data - 0912b06e3222dffe316272c990da4132
                                .rsrc - a73cb8def8692c459b2a0f7c06d906a8
                                .text - d3e2a31be52987b6145cb54b8163b00a
                                .reloc - e8375034a29b251523a59af7baa20a55
              pe_debug_version: 0.0
                           tag: pe_custom_resource_type
          pe_section_alignment: 4096
         pe_import_hash_sorted: b33210d31008ec6810cdcdf3aab1e036
         pe_stack_reserve_size: 262144
    pe_section_virtual_address: .text - 4096
                                .data - 520192
                                .rsrc - 581632
                                .reloc - 1052672
                pe_header_size: 1024
      pe_import_function_count: d3dxof.dll - 1
                                USER32.dll - 5
                                MSACM32.dll - 6
                                OLEAUT32.dll - 6
                                ADVAPI32.dll - 8
                                GDI32.dll - 15
                                ole32.dll - 15
                                MSVCRT.dll - 31
                                KERNEL32.dll - 58
       pe_section_relocs_count: .data - 0
                                .reloc - 0
                                .rsrc - 0
                                .text - 0
                    pe_machine: I386
              pe_resource_name: 230f76986b2ecdd5b30cb86e5782bbc553592c33fb2d455185ac744b649a9d95 - 1
                                422a899d71fead1ea92c9e1695a60a96c4ae69c642052e5c6145bb5df560602d - 1
                                c3602f46f15965449c3da5f81f3e393aa964ee5e3d82ffe68c5b290767dfc81b - 1
                                d05302600e4da5ed9c8cf153af840fbacb4cf5816ff92d0b00e3fd0c79f366a6 - 1
                   pe_resource: 230f76986b2ecdd5b30cb86e5782bbc553592c33fb2d455185ac744b649a9d95
                                422a899d71fead1ea92c9e1695a60a96c4ae69c642052e5c6145bb5df560602d
                                c3602f46f15965449c3da5f81f3e393aa964ee5e3d82ffe68c5b290767dfc81b
                                d05302600e4da5ed9c8cf153af840fbacb4cf5816ff92d0b00e3fd0c79f366a6
       pe_import_function_hint: d3dxof.dll!DirectXFileCreate - 0
                                ole32.dll!CoCreateGuid - 14
                                ole32.dll!CoCreateInstance - 15
                                KERNEL32.dll!CloseHandle - 33
                                MSACM32.dll!acmStreamClose - 36
                                MSACM32.dll!acmStreamConvert - 37
                                MSACM32.dll!acmStreamOpen - 39
                                MSACM32.dll!acmStreamPrepareHeader - 40
                                USER32.dll!CharNextA - 40
                                ...
          pe_heap_reserve_size: 1048576
               pe_compile_time: 2000-10-21 09:22:24
                 pe_image_base: 4194304
           pe_uninit_data_size: 0
             pe_init_data_size: 555520
              pe_image_version: 5.1
            pe_debug_timestamp: 2000-10-21 09:22:24
                  pe_subsystem: WINDOWS_GUI
           pe_section_raw_size: .reloc - 26112
                                .data - 57344
                                .rsrc - 468480
                                .text - 516096
          pe_resource_language: 230f76986b2ecdd5b30cb86e5782bbc553592c33fb2d455185ac744b649a9d95 - ENGLISH US
                                422a899d71fead1ea92c9e1695a60a96c4ae69c642052e5c6145bb5df560602d - ENGLISH US
                                c3602f46f15965449c3da5f81f3e393aa964ee5e3d82ffe68c5b290767dfc81b - ENGLISH US
                                d05302600e4da5ed9c8cf153af840fbacb4cf5816ff92d0b00e3fd0c79f366a6 - ENGLISH US
        pe_section_raw_address: .text - 1024
                                .data - 517120
                                .rsrc - 574464
                                .reloc - 1042944
                 pe_debug_type: CODEVIEW
    pe_export_function_address: DllCanUnloadNow - 62332
                                DllGetClassObject - 62344
                                DllRegisterServer - 62369
                                DllUnregisterServer - 62567
                                VB_NewBuffer - 163813
                                VB_GetDataFromBuffer - 164060
                                VB_GetStringFromBuffer - 164207
                                VB_AddStringToBuffer - 164454
                                ...
             pe_linker_version: 6.20
              pe_resource_type: 230f76986b2ecdd5b30cb86e5782bbc553592c33fb2d455185ac744b649a9d95 - #2147483952
                                c3602f46f15965449c3da5f81f3e393aa964ee5e3d82ffe68c5b290767dfc81b - #2147483976
                                d05302600e4da5ed9c8cf153af840fbacb4cf5816ff92d0b00e3fd0c79f366a6 - RT_STRING
                                422a899d71fead1ea92c9e1695a60a96c4ae69c642052e5c6145bb5df560602d - RT_VERSION
            pe_import_function: MSVCRT.dll - ?terminate@@YAXXZ
                                USER32.dll - CharNextA
                                KERNEL32.dll - CloseHandle
                                ole32.dll - CoCreateGuid
                                ole32.dll - CoCreateInstance
                                ole32.dll - CoGetInterfaceAndReleaseStream
                                ole32.dll - CoInitialize
                                ole32.dll - CoInitializeEx
                                ole32.dll - CoMarshalInterThreadInterfaceInStream
                                MSVCRT.dll - wcslen
                                USER32.dll - wsprintfA
                                ...
          pe_stack_commit_size: 4096
                 pe_image_size: 1081344

Feature key:
  pe_characteristics:  Characteristics as defined in the PE file header
  pe_checksum:  Checksum as defined in PE optional header
  pe_code_base:  Code base as defined in PE optional header
  pe_code_size:  Code size as defined in PE optional header
  pe_compile_time:  PE Compile Time
  pe_data_base:  Data base as defined in PE optional header
  pe_debug_characteristics:  Characteristics of debug (should be zero)
  pe_debug_offset:  Raw file offset to debug information
  pe_debug_size:  Size of debug record
  pe_debug_timestamp:  Debug data creation time and date
  pe_debug_type:  Format of debugging information
  pe_debug_version:  Version number of the debug data format
  pe_entry_point:  Entry point address as defined in PE optional header
  pe_export:  Name of the DLL exported
  pe_export_base:  Base ordinal of the exported functions
  pe_export_characteristics:  Characteristics of the DLL exported
  pe_export_count:  Number of exported functions
  pe_export_function:  Name of the exported function
  pe_export_function_address:  Address of the exported function
  pe_export_function_ordinal:  Ordinal of the exported function
  pe_export_time:  Time the DLL was exported
  pe_export_version:  Version of the DLL exported
  pe_file_alignment:  File alignment as defined in PE optional header
  pe_header_size:  Header size as defined in PE optional header
  pe_heap_commit_size:  Heap commit size as defined in PE optional header
  pe_heap_reserve_size:  Heap reserve size as defined in PE optional header
  pe_image_base:  Image base as defined in PE optional header
  pe_image_size:  Image size as defined in PE optional header
  pe_image_version:  Image version as defined in PE optional header
  pe_import_function:  Name of the function imported from the module
  pe_import_function_count:  Count of the functions imported from the module
  pe_import_function_fullname:  Concatenated module and function name/ordinal
  pe_import_function_hint:  Hint for the labelled function
  pe_import_function_ordinal:  Ordinal of the function imported from the module
  pe_import_hash:  MD5 hash of the import entries
  pe_import_hash_sorted:  MD5 hash of the sorted import entries
  pe_import_module:  Name of the module imported
  pe_import_module_count:  Count of modules imported
  pe_init_data_size:  Initialised data size as defined in PE optional header
  pe_linker_version:  Linker version as defined in PE optional header
  pe_loader_flags:  Loader flags as defined in PE optional header
  pe_machine:  Machine as defined in PE file header
  pe_num_rva_and_sizes:  Number of data directories from PE optional header
  pe_os_version:  Operating system version as defined in PE optional header
  pe_resource:  SHA256 hash of the embedded PE resource
  pe_resource_language:  Language of the PE resource labelled by resource hash
  pe_resource_name:  Name of the PE resource labelled by resource hash
  pe_resource_size:  Size of the PE resource labelled by resource hash
  pe_resource_type:  Type of the PE resource labelled by resource hash
  pe_section:  Name of the PE section
  pe_section_alignment:  Section alignment as defined in PE optional header
  pe_section_characteristics:  Characteristics of the section
  pe_section_count:  Number of sections
  pe_section_hash:  MD5 of the contents of the section
  pe_section_line_nums_address:  Raw file offset of the line nums for the section
  pe_section_line_nums_count:  Number of line numbers for the section
  pe_section_raw_address:  Raw file offset of the section
  pe_section_raw_size:  Raw size of the section
  pe_section_relocs_address:  Raw file offset of the relocations for the section
  pe_section_relocs_count:  Number of relocations for the section
  pe_section_virtual_address:  Virtual address of the section
  pe_section_virtual_size:  Virtual size of the section
  pe_stack_commit_size:  Stack commit size as defined in PE optional header
  pe_stack_reserve_size:  Stack reserve size as defined in PE optional header
  pe_subsystem:  Target subsystem as defined in PE optional header
  pe_subsystem_version:  Subsystem version as defined in PE optional header
  pe_uninit_data_size:  Uninitialised data size as defined in PE optional header
  pe_win32_version:  Win32 version as defined in PE optional header
  tag:  Any informational label about the binary

Generated child entities (4):
  {'action': 'extracted', 'type': 'resource', 'name': '1', 'restype': '#2147483952'} <binary: 230f76986b2ecdd5b30cb86e5782bbc553592c33fb2d455185ac744b649a9d95>
    content: 27 bytes
  {'action': 'extracted', 'type': 'resource', 'name': '1', 'restype': '#2147483976'} <binary: c3602f46f15965449c3da5f81f3e393aa964ee5e3d82ffe68c5b290767dfc81b>
    content: 466744 bytes
  {'action': 'extracted', 'type': 'resource', 'name': '1', 'restype': 'RT_STRING'} <binary: d05302600e4da5ed9c8cf153af840fbacb4cf5816ff92d0b00e3fd0c79f366a6>
    content: 124 bytes
  {'action': 'extracted', 'type': 'resource', 'name': '1', 'restype': 'RT_VERSION'} <binary: 422a899d71fead1ea92c9e1695a60a96c4ae69c642052e5c6145bb5df560602d>
    content: 876 bytes
```

Automated usage in system:

```
azul-lief-pe --server http://azul-dispatcher.localnet/
```

## Usage: azul-lief-macho

Parses Apple Mach-O Executables (excluding FAT Mach-O's).

Features available executable metadata, including:

- Header Fields
- Imports/Exports
- Load Commands

Usage on local files:

```
azul-lief-macho sample
```

Example Output:

```
----- LiefMachO results -----
OK

Output features:
                          macho_load_command_type: 1168 - BUILD_VERSION
                                                   1336 - DATA_IN_CODE
                                                   960 - DYLD_INFO_ONLY
                                                   1032 - DYSYMTAB
                                                   1240 - ENCRYPTION_INFO_64
                                                   1320 - FUNCTION_STARTS
                                                   1264 - LOAD_DYLIB
                                                   1112 - LOAD_DYLINKER
                                                   1216 - MAIN
                                                   104 - SEGMENT_64
                                                   32 - SEGMENT_64
                                                   496 - SEGMENT_64
                                                   888 - SEGMENT_64
                                                   1200 - SOURCE_VERSION
                                                   1008 - SYMTAB
                                                   1144 - UUID
                    macho_section_virtual_address: __TEXT.__text - 4294987868
                                                   __TEXT.__cstring - 4295062444
                                                   __TEXT.__const - 4295065256
                                                   __TEXT.__unwind_info - 4295065412
                                                   __DATA.__objc_imageinfo - 4311744512
                                                   __DATA.__data - 4311744520
                                                   __DATA.__file - 4311744808
                                                   __DATA.__common - 4311873400
                  macho_symbol_table_strings_size: 229504 - 48
                     macho_segment_sections_count: __LINKEDIT - 0
                                                   __PAGEZERO - 0
                                                   __DATA - 4
                                                   __TEXT - 4
             macho_dynamic_symbol_undefined_count: 1 - 1
                       macho_encryption_info_size: 16384 - 81920
                               macho_section_name: __DATA - __common
                                                   __TEXT - __const
                                                   __TEXT - __cstring
                                                   __DATA - __data
                                                   __DATA - __file
                                                   __DATA - __objc_imageinfo
                                                   __TEXT - __text
                                                   __TEXT - __unwind_info
                         macho_segment_raw_offset: __PAGEZERO - 0
                                                   __TEXT - 0
                                                   __DATA - 98304
                                                   __LINKEDIT - 229376
                                       macho_uuid: 73c348fd-68e0-dc35-a6ad-96b32312322c
           macho_dyld_info_lazy_bind_opcodes_hash: 0 - d41d8cd98f00b204e9800998ecf8427e
                          macho_load_command_hash: 1320 - 075c2159c11c8166df7e77c91e873bab
                                                   496 - 359c552ff2b9e529873f60888b0fab84
                                                   1112 - 43383bb1d7140faa1208171d4c2b9f78
                                                   1144 - 4f7ad4f92d6c386af39599c55d4914bd
                                                   1032 - 5259733b3e3669853b799aca94c99205
                                                   1264 - a1270ca0a5eabe10a5be95f63f4080aa
                                                   1200 - a38d65ede3a5c7463297b11912f3d55d
                                                   1336 - b7bdb3817a68acfc071ff487e9d55caf
                                                   32 - c3c28a449168406e65f72c42aeb3574f
                                                   888 - c9d053d042eba9fa4289df37fb073fa9
                                                   1216 - ce5c425ad52f89f7e37b5091257e0106
                                                   104 - cee2652f6e8e38face8eb20a5a205931
                                                   960 - ebe2fc4fb1a9450e371738d1b4deafd9
                                                   1008 - ec9a8cb8c3693abe70fcbcb16141ec31
                                                   1168 - f182277f2de40b0cb59b99cacd36041d
                                                   1240 - f7094389672295fb0a730e26c53a94d9
                                macho_cpu_subtype: ARM64_ALL
                 macho_section_relocations_offset: __DATA.__common - 0
                                                   __DATA.__data - 0
                                                   __DATA.__file - 0
                                                   __DATA.__objc_imageinfo - 0
                                                   __TEXT.__const - 0
                                                   __TEXT.__cstring - 0
                                                   __TEXT.__text - 0
                                                   __TEXT.__unwind_info - 0
                             macho_commands_count: 16
                            macho_function_starts: 54
                                      macho_magic: MAGIC_64
           macho_dyld_info_weak_bind_opcodes_hash: 0 - d41d8cd98f00b204e9800998ecf8427e
                           macho_section_fullname: __DATA.__common
                                                   __DATA.__data
                                                   __DATA.__file
                                                   __DATA.__objc_imageinfo
                                                   __TEXT.__const
                                                   __TEXT.__cstring
                                                   __TEXT.__text
                                                   __TEXT.__unwind_info
      macho_dynamic_symbol_indirect_symbol_offset: 0
                                macho_export_name: __mh_execute_header
                    macho_segment_virtual_address: __PAGEZERO - 0
                                                   __TEXT - 4294967296
                                                   __LINKEDIT - 4295065600
                                                   __DATA - 4311744512
                               macho_section_hash: __DATA.__data - 38b1e8eafcb6c150d2b6f23c51209098
                                                   __TEXT.__text - 48842ccd1cd9affb3379d781e9432603
                                                   __DATA.__objc_imageinfo - 7373e16c29e882b74cf3e99ee6602166
                                                   __TEXT.__unwind_info - 75b439d78199b23cf8310aa5777b2d45
                                                   __TEXT.__const - a990c4a9834bdfc5be240a0baaca7ce9
                                                   __DATA.__common - d41d8cd98f00b204e9800998ecf8427e
                                                   __TEXT.__cstring - e90a3af3d28570fc099232e93aab0190
                                                   __DATA.__file - ef26ae2ddd4cda98fd3d31c6cb657478
                     macho_function_starts_offset: 229408
                       macho_dylib_compat_version: /usr/lib/libSystem.B.dylib - 1.0.0
                      macho_dyld_info_rebase_size: 0 - 0
   macho_dynamic_symbol_external_relocation_count: 0 - 0
                            macho_dylib_timestamp: /usr/lib/libSystem.B.dylib - 2
                             macho_export_address: __mh_execute_header - 0
       macho_dynamic_symbol_indirect_symbol_count: 0 - 0
                     macho_encryption_info_offset: 16384
                  macho_segment_relocations_count: __DATA - 0
                                                   __LINKEDIT - 0
                                                   __PAGEZERO - 0
                                                   __TEXT - 0
                        macho_dynamic_linker_name: /usr/lib/dyld
                    macho_dyld_info_rebase_offset: 0
                          macho_section_alignment: __DATA.__file - 0
                                                   __TEXT.__cstring - 0
                                                   __DATA.__objc_imageinfo - 2
                                                   __TEXT.__const - 2
                                                   __TEXT.__text - 2
                                                   __TEXT.__unwind_info - 2
                                                   __DATA.__common - 3
                                                   __DATA.__data - 3
                   macho_dynamic_symbol_toc_count: 0 - 0
             macho_dynamic_symbol_undefined_index: 1
                 macho_dyld_info_weak_bind_offset: 0
   macho_dynamic_symbol_external_reference_offset: 0
                          macho_load_command_size: 1200 - 16
                                                   1320 - 16
                                                   1336 - 16
                                                   1008 - 24
                                                   1144 - 24
                                                   1216 - 24
                                                   1240 - 24
                                                   1112 - 32
                                                   1168 - 32
                                                   960 - 48
                                                   1264 - 56
                                                   32 - 72
                                                   888 - 72
                                                   1032 - 80
                                                   104 - 392
                                                   496 - 392
                         macho_load_command_count: BUILD_VERSION - 1
                                                   DATA_IN_CODE - 1
                                                   DYLD_INFO_ONLY - 1
                                                   DYSYMTAB - 1
                                                   ENCRYPTION_INFO_64 - 1
                                                   FUNCTION_STARTS - 1
                                                   LOAD_DYLIB - 1
                                                   LOAD_DYLINKER - 1
                                                   MAIN - 1
                                                   SOURCE_VERSION - 1
                                                   SYMTAB - 1
                                                   UUID - 1
                                                   SEGMENT_64 - 4
                               macho_segment_hash: __TEXT - 1c6b8e7befafc9040f0c9882f4eb0252
                                                   __DATA - 43143e00722762abf84764b251441006
                                                   __PAGEZERO - d41d8cd98f00b204e9800998ecf8427e
                                                   __LINKEDIT - e14c3e4fd77faccb58b53f3dea02bde5
                                macho_header_flag: DYLDLINK
                                                   NOUNDEFS
                                                   PIE
                                                   TWOLEVEL
          macho_dynamic_symbol_module_table_count: 0 - 0
                         macho_encryption_info_id: 16384 - 0
                    macho_segment_init_protection: __PAGEZERO - 00000000
                                                   __LINKEDIT - 00000001
                                                   __DATA - 00000003
                                                   __TEXT - 00000005
                macho_dyld_info_bind_opcodes_hash: 0 - d41d8cd98f00b204e9800998ecf8427e
      macho_dynamic_symbol_external_defined_index: 0
                macho_symbol_table_strings_offset: 229504 - 229536
                      macho_dyld_info_export_size: 229376 - 32
                               macho_section_type: __TEXT.__cstring - CSTRING_LITERALS
                                                   __DATA.__data - REGULAR
                                                   __DATA.__file - REGULAR
                                                   __DATA.__objc_imageinfo - REGULAR
                                                   __TEXT.__const - REGULAR
                                                   __TEXT.__text - REGULAR
                                                   __TEXT.__unwind_info - REGULAR
                                                   __DATA.__common - ZEROFILL
                               macho_section_flag: __TEXT.__text - PURE_INSTRUCTIONS
                                                   __TEXT.__text - SOME_INSTRUCTIONS
                        macho_load_command_offset: 32
                                                   104
                                                   496
                                                   888
                                                   960
                                                   1008
                                                   1032
                                                   1112
                                                   1144
                                                   1168
                                                   1200
                                                   1216
                                                   1240
                                                   1264
                                                   1320
                                                   1336
      macho_dynamic_symbol_local_relocation_count: 0 - 0
                             macho_source_version: 0.0.0.0.0
                 macho_symbol_table_symbols_count: 229504 - 2
                            macho_main_stack_size: 26180 - 0
                   macho_dyld_info_lazy_bind_size: 0 - 0
     macho_dynamic_symbol_local_relocation_offset: 0
         macho_dynamic_symbol_module_table_offset: 0
    macho_dynamic_symbol_external_reference_count: 0 - 0
                 macho_dyld_info_lazy_bind_offset: 0
                        macho_data_in_code_offset: 229504
                            macho_main_entrypoint: 26180
                       macho_segment_virtual_size: __LINKEDIT - 208
                                                   __TEXT - 98304
                                                   __DATA - 163840
                                                   __PAGEZERO - 4294967296
                             macho_section_offset: __DATA.__common - 0
                                                   __TEXT.__text - 20572
                                                   __TEXT.__cstring - 95148
                                                   __TEXT.__const - 97960
                                                   __TEXT.__unwind_info - 98116
                                                   __DATA.__objc_imageinfo - 98304
                                                   __DATA.__data - 98312
                                                   __DATA.__file - 98600
                              macho_commands_size: 1320
                                  macho_file_type: EXECUTE
                           macho_section_reserved: __DATA.__common - 00000000.00000000.00000000
                                                   __DATA.__data - 00000000.00000000.00000000
                                                   __DATA.__file - 00000000.00000000.00000000
                                                   __DATA.__objc_imageinfo - 00000000.00000000.00000000
                                                   __TEXT.__const - 00000000.00000000.00000000
                                                   __TEXT.__cstring - 00000000.00000000.00000000
                                                   __TEXT.__text - 00000000.00000000.00000000
                                                   __TEXT.__unwind_info - 00000000.00000000.00000000
                      macho_dylib_current_version: /usr/lib/libSystem.B.dylib - 1252.200.5
                 macho_dynamic_symbol_local_index: 0
                        macho_symbol_table_offset: 229504
                               macho_section_size: __DATA.__objc_imageinfo - 8
                                                   __TEXT.__const - 156
                                                   __TEXT.__unwind_info - 188
                                                   __DATA.__data - 288
                                                   __TEXT.__cstring - 2811
                                                   __DATA.__common - 21580
                                                   __TEXT.__text - 74576
                                                   __DATA.__file - 128592
                          macho_data_in_code_size: 229504 - 0
                                   macho_cpu_type: ARM64
      macho_dynamic_symbol_external_defined_count: 0 - 1
                   macho_dyld_info_weak_bind_size: 0 - 0
                  macho_section_relocations_count: __DATA.__common - 0
                                                   __DATA.__data - 0
                                                   __DATA.__file - 0
                                                   __DATA.__objc_imageinfo - 0
                                                   __TEXT.__const - 0
                                                   __TEXT.__cstring - 0
                                                   __TEXT.__text - 0
                                                   __TEXT.__unwind_info - 0
                               macho_load_command: BUILD_VERSION
                                                   DATA_IN_CODE
                                                   DYLD_INFO_ONLY
                                                   DYSYMTAB
                                                   ENCRYPTION_INFO_64
                                                   FUNCTION_STARTS
                                                   LOAD_DYLIB
                                                   LOAD_DYLINKER
                                                   MAIN
                                                   SEGMENT_64
                                                   SOURCE_VERSION
                                                   SYMTAB
                                                   UUID
  macho_dynamic_symbol_external_relocation_offset: 0
                  macho_dynamic_symbol_toc_offset: 0
                                 macho_dylib_name: /usr/lib/libSystem.B.dylib
                           macho_segment_raw_size: __PAGEZERO - 0
                                                   __LINKEDIT - 208
                                                   __TEXT - 98304
                                                   __DATA - 131072
                              macho_segment_flags: __DATA - 00000000
                                                   __LINKEDIT - 00000000
                                                   __PAGEZERO - 00000000
                                                   __TEXT - 00000000
                                macho_export_kind: __mh_execute_header - REGULAR
                       macho_function_starts_size: 229408 - 96
                               macho_segment_name: __DATA
                                                   __LINKEDIT
                                                   __PAGEZERO
                                                   __TEXT
                 macho_dynamic_symbol_local_count: 0 - 0
                            macho_header_reserved: 0
              macho_dyld_info_rebase_opcodes_hash: 0 - d41d8cd98f00b204e9800998ecf8427e
                        macho_dyld_info_bind_size: 0 - 0
                     macho_segment_max_protection: __PAGEZERO - 00000000
                                                   __LINKEDIT - 00000001
                                                   __DATA - 00000003
                                                   __TEXT - 00000005
                      macho_dyld_info_bind_offset: 0
                    macho_dyld_info_export_offset: 229376

Feature key:
  macho_commands_count:  Number of load commands in Mach-O
  macho_commands_size:  Size of all load commands in Mach-O
  macho_cpu_subtype:  CPU subtype of Mach-O
  macho_cpu_type:  CPU type of Mach-O
  macho_data_in_code_offset:  Offset in the binary to the data in code table
  macho_data_in_code_size:  Size of the data in code table
  macho_dyld_info_bind_offset:  Offset in file of the bind information
  macho_dyld_info_bind_opcodes_hash:  MD5 hash of the bind opcodes
  macho_dyld_info_bind_size:  Size of the bind information
  macho_dyld_info_export_offset:  Offset in the file of the export information
  macho_dyld_info_export_size:  Size of the export information
  macho_dyld_info_lazy_bind_offset:  Offset in file of the lazy bind information
  macho_dyld_info_lazy_bind_opcodes_hash:  MD5 hash of the lazy bind opcodes
  macho_dyld_info_lazy_bind_size:  Size of the lazy bind information
  macho_dyld_info_rebase_offset:  Offset in file of the rebase information
  macho_dyld_info_rebase_opcodes_hash:  MD5 hash of the rebase opcodes
  macho_dyld_info_rebase_size:  Size of the rebase information
  macho_dyld_info_weak_bind_offset:  Offset in file of the weak bind information
  macho_dyld_info_weak_bind_opcodes_hash:  MD5 hash of the weak bind opcodes
  macho_dyld_info_weak_bind_size:  Size of the weak bind information
  macho_dylib_compat_version:  Compatibility version of dylib
  macho_dylib_current_version:  Current version of dylib
  macho_dylib_name:  Name of dylib
  macho_dylib_timestamp:  Name of dylib
  macho_dynamic_linker_name:  Name of dynamic linker (for self-identification)
  macho_dynamic_symbol_external_defined_count:  Count of symbols in defined external group
  macho_dynamic_symbol_external_defined_index:  Index to group of defined external symbols
  macho_dynamic_symbol_external_reference_count:  Number of entries in the external references table, should be zero
  macho_dynamic_symbol_external_reference_offset:  Byte offset from start of file to the external reference table data, should be zero
  macho_dynamic_symbol_external_relocation_count:  Number of entries in the external relocation table, should be zero
  macho_dynamic_symbol_external_relocation_offset:  Byte offset from start of file to the external relocation table data, should be zero
  macho_dynamic_symbol_indirect_symbol_count:  Number of entries in the indirect symbol table
  macho_dynamic_symbol_indirect_symbol_offset:  Byte offset from start of file to the indirect symbol table data
  macho_dynamic_symbol_local_count:  Number of symbols in group of local symbols
  macho_dynamic_symbol_local_index:  Index of first symbol in group of local symbols
  macho_dynamic_symbol_local_relocation_count:  Number of entries in the local relocation table, should be zero
  macho_dynamic_symbol_local_relocation_offset:  Byte offset from start of file to the local relocation table data, should be zero
  macho_dynamic_symbol_module_table_count:  Number of entries in the module table, should be zero
  macho_dynamic_symbol_module_table_offset:  Byte offset from start of file to the module table data, should be zero
  macho_dynamic_symbol_toc_count:  Number of entries in the table of contents, should be zero
  macho_dynamic_symbol_toc_offset:  Byte offset from start of file to the table of contents, should be zero
  macho_dynamic_symbol_undefined_count:  Count of symbols in the undefined external group
  macho_dynamic_symbol_undefined_index:  First symbol index in group of undefined external symbols
  macho_encryption_info_id:  Encryption system ID to use, 0 means not encrypted
  macho_encryption_info_offset:  Offset in file to the encryption information
  macho_encryption_info_size:  Size of the encryption information
  macho_export_address:  Address of the exported symbol
  macho_export_kind:  Kind of exported symbol
  macho_export_name:  Exported symbol name
  macho_file_type:  File type of Mach-O
  macho_function_starts:  Number of function starts indicated in binary
  macho_function_starts_offset:  Offset in file to the function starts table
  macho_function_starts_size:  Size of the functions list in the binary
  macho_header_flag:  Flags set in Mach-O header
  macho_header_reserved:  Reserved field in Mach-O, should be zero
  macho_load_command:  Type of load command in binary
  macho_load_command_count:  Number of commands with given type
  macho_load_command_hash:  MD5 hash of load command data
  macho_load_command_offset:  Offset into load command table
  macho_load_command_size:  Size of load command data
  macho_load_command_type:  Load command type for offset
  macho_magic:  Magic value of Mach-O indicating endianess
  macho_main_entrypoint:  Program entry point
  macho_main_stack_size:  Program stack size
  macho_section_alignment:  Alignment of the section
  macho_section_flag:  Flags of section
  macho_section_fullname:  Full name of the section in segment
  macho_section_hash:  MD5 hash of data in section
  macho_section_name:  Name of the section in segment
  macho_section_offset:  Offset of data in file for section
  macho_section_relocations_count:  Number of relocations for section
  macho_section_relocations_offset:  Relocation data offset in file for section
  macho_section_reserved:  Reserved data in section
  macho_section_size:  Size of the section
  macho_section_type:  Type of section
  macho_section_virtual_address:  Virtual address of section
  macho_segment_flags:  Flags of segment
  macho_segment_hash:  MD5 of the segment data
  macho_segment_init_protection:  Initial protection for segment
  macho_segment_max_protection:  Maximum protection for segment
  macho_segment_name:  Name of segment in Mach-O file
  macho_segment_raw_offset:  Offset of data in file for segment
  macho_segment_raw_size:  Size of data in file for segment
  macho_segment_relocations_count:  Number of relocations in segment
  macho_segment_sections_count:  Number of sections in segment
  macho_segment_virtual_address:  Virtual address of segment
  macho_segment_virtual_size:  Virtual size of segment
  macho_source_version:  Version of the source used to build the binary
  macho_symbol_table_offset:  Offset in file to symbol table
  macho_symbol_table_strings_offset:  Offset in file to the strings table
  macho_symbol_table_strings_size:  Size of the strings table
  macho_symbol_table_symbols_count:  Number of symbols in the symbol table
  macho_uuid:  UUID added by the linker to the Mach-O
```

Automated usage in system:

```
azul-lief-macho --server http://azul-dispatcher.localnet/
```

## Usage: azul-fat-macho

Parses FAT Mach-O files, featuring and extracting the contained architecture binaries.

Usage on local files:

```
azul-fat-macho fat_sample
```

Example Output:

```
----- FatMachO results -----
OK

Output features:
     fat_macho_binary_cpu_type: 16384 - ARM
                                23642112 - ARM
                                47267840 - ARM64
    fat_macho_binary_alignment: 16384 - 14
                                23642112 - 14
                                47267840 - 14
               fat_macho_magic: cafebabe
        fat_macho_binary_count: 3
  fat_macho_binary_cpu_subtype: 47267840 - ARM64_ALL
                                16384 - ARM_V7
                                23642112 - ARM_V7S
       fat_macho_binary_offset: 16384
                                23642112
                                47267840
         fat_macho_binary_size: 23642112 - 23611392
                                16384 - 23611408
                                47267840 - 27595216

Feature key:
  fat_macho_binary_alignment:  Alignment of the contained binary
  fat_macho_binary_count:  Number of binaries contained in the Mach-O
  fat_macho_binary_cpu_subtype:  CPU subtype targeted by the contained binary
  fat_macho_binary_cpu_type:  CPU type targeted by the contained binary
  fat_macho_binary_offset:  Offset of the contained binary
  fat_macho_binary_size:  Size of the contained binary
  fat_macho_magic:  Magic value of Mach-O indicating endianess

Generated child entities (3):
  {'action': 'extracted', 'offset': '0x4000', 'cpu_type': 'ARM', 'cpu_subtype': 'ARM_V7'} <binary: b897fa81c7abdb2730bd9713f9053369d40a045c83a6c79d663c91a2bb6b1d03>
    content: 23611408 bytes
  {'action': 'extracted', 'offset': '0x168c000', 'cpu_type': 'ARM', 'cpu_subtype': 'ARM_V7S'} <binary: c9fa57b929762bdaeab3c96ddcc8ef728d7749d79b1b6d3b6edb5d43d3e4c9b1>
    content: 23611392 bytes
  {'action': 'extracted', 'offset': '0x2d14000', 'cpu_type': 'ARM64', 'cpu_subtype': 'ARM64_ALL'} <binary: 345d8cd161fee2a948666de409a8ec9dc34648b236fc82884c0164b18bd7b628>
    content: 27595216 bytes
```

Automated usage in system:

```
azul-fat-macho --server http://azul-dispatcher.localnet/
```

## Usage: azul-lief-elf

Parses Linux/BSD/... ELF Executables.

Features available executable metadata, including:

- Header Fields
- Imports/Exports
- Android/Compiler Notes

**Files which export more than 1000 symbols (the Max Values Per Feature runner config option value) will have truncated results.**

Usage on local files:

```
azul-lief-elf sample
```

Example Output:

```
----- LiefELF results -----
OK

events (1)

event for binary:0d06f9724af41b13cdacea133530b9129a48450230feef9632d53d5bbb837c8c:None
  {}
  output features:
                 elf_abi_version: 0
                       elf_class: CLASS64
                        elf_data: 2's complement, little endian
                  elf_entrypoint: 22608
                      elf_export: Version
                                  ...
                                  stdout
                                  version_etc_copyright
              elf_export_binding: Version - GLOBAL
                                  ...
                                  version_etc_copyright - GLOBAL
                                  program_invocation_name - WEAK
                                  program_invocation_short_name - WEAK
                 elf_export_size: _fini - 0
                                  ...
                                  _obstack_newchunk - 235
                 elf_export_type: _fini - FUNC
                                  ...
                                  version_etc_copyright - OBJECT
                elf_export_value: _init - 14168
                                  ...
                                  program_name - 2233344
              elf_export_version: Version - * Global *
                                  _IO_stdin_used - * Global *
                                  ...
                                  stderr - GLIBC_2.2.5(3)
                                  stdout - GLIBC_2.2.5(3)
           elf_export_visibility: Version - DEFAULT
                                  _IO_stdin_used - DEFAULT
                                  __progname - DEFAULT
                                  ...
                                  stderr - DEFAULT
                                  stdout - DEFAULT
                                  version_etc_copyright - DEFAULT
                 elf_hdr_version: 1 (current)
                 elf_header_size: 64
                      elf_import: __assert_fail
                                  __ctype_b_loc
                                  ...
                                  wcwidth
              elf_import_binding: __assert_fail - GLOBAL
                                  ...
                                  wcwidth - GLOBAL
                                  __cxa_finalize - WEAK
                 elf_import_size: __assert_fail - 0
                                  __ctype_b_loc - 0
                                  ...
                                  wcswidth - 0
                                  wcwidth - 0
                 elf_import_type: __assert_fail - FUNC
                                  __ctype_b_loc - FUNC
                                 ...
                                  wcswidth - FUNC
                                  wcwidth - FUNC
                elf_import_value: __assert_fail - 0
                                  __ctype_b_loc - 0
                                  __ctype_get_mb_cur_max - 0
                                  ...
                                  wcswidth - 0
                                  wcwidth - 0
              elf_import_version: fgetfilecon - * Local *
                                  freecon - * Local *
                                  getfilecon - * Local *
                                  ...
                                  __stack_chk_fail - GLIBC_2.4(6)
           elf_import_visibility: __assert_fail - DEFAULT
                                  ...
                                  wcswidth - DEFAULT
                                  wcwidth - DEFAULT
                     elf_machine: Advanced Micro Devices X86-64
                        elf_note: 0
                                  1
                    elf_note_abi: 0 - NOTE_ABIS.LINUX
            elf_note_description: 0 - 00 00 00 00 03 00 00 00 02 00 00 00 00 00 00 00
                                  1 - 95 67 f9 a2 8e 66 f4 d7 ec 4b af 31 cf bf 68 d0 41 0f 0a e6
                   elf_note_name: 0 - GNU
                                  1 - GNU
                   elf_note_type: 0 - ABI_TAG
                                  1 - BUILD_ID
                elf_note_version: 0 - 3.2.0
            elf_num_prog_headers: 9
         elf_num_section_headers: 28
                 elf_obj_version: 0x1
                      elf_os_abi: UNIX - System V
              elf_processor_flag: 0
       elf_program_header_offset: 64
         elf_program_header_size: 56
                     elf_section:
                                  .bss
                                  .data
                                  .data.rel.ro
                                  ...
                                  .rela.plt
                                  .rodata
                                  .shstrtab
                                  .text
           elf_section_alignment: 0
                                  .dynstr - 1
                                  .interp - 1
                                  .shstrtab - 1
                                  .gnu.version - 2
                                  .eh_frame_hdr - 4
                                  ...
                                  .data - 32
                                  .data.rel.ro - 32
                                  .rodata - 32
             elf_section_entropy: 0.0
                                  .bss - 0.0
                                  .fini_array - 1.061278124459133
                                  .init_array - 1.061278124459133
                                  .data - 1.3372769059938467
                                  ...
                                  .text - 6.290053617606062
          elf_section_entry_size: 0
                                  .bss - 0
                                  .data - 0
                                  .data.rel.ro - 0
                                  ...
                                  .rela.dyn - 24
                                  .rela.plt - 24
               elf_section_flags:
                                  .gnu_debuglink -
                                  .shstrtab -
                                  .dynstr - A
                                  ...
                                  .got - WA
                                  .init_array - WA
                elf_section_hash: .data - 04df3a25922910e50972f7bb02082e7def49833e79d526f8c080d152e26d38c6
                                  .got - 11bbd4b0e640d96947142a658aa1b78acaacace6f91a00b026a7286c5dd7a248
                                  ...
                                  .rela.dyn - fff394f3f3d1043240c64c4ceed1697302139de130fe2a00268468f0f7662086
       elf_section_header_offset: 132000
         elf_section_header_size: 64
         elf_section_information: 0
                                  .bss - 0
                                  .data - 0
                                  ...
                                  .gnu.version_r - 1
                                  .rela.plt - 23
                elf_section_link: 0
                                  .bss - 0
                                  .data - 0
                                  ...
                                  .dynamic - 6
                                  .dynsym - 6
                                  .gnu.version_r - 6
      elf_section_name_table_idx: 27
           elf_section_num_flags: 0
                                  .gnu_debuglink - 0
                                  .shstrtab - 0
                                  ...
                                  .plt.got - 6
                                  .text - 6
                                  .rela.plt - 66
            elf_section_segments:
                                  .gnu_debuglink -
                                  .shstrtab -
                                  ...
                                  .init_array - LOAD - GNU_RELRO
                                  .note.ABI-tag - LOAD - NOTE
                                  .note.gnu.build-id - LOAD - NOTE
                elf_section_type: .dynamic - DYNAMIC
                                  ...
                                  .gnu.version_r - VERNEED
                                  .gnu.version - VERSYM
     elf_section_virtual_address: 0
                                  .gnu_debuglink - 0
                                  ...
                                  .data - 2228224
                                  .bss - 2228864
                     elf_segment: 0
                                  ...
                                  7
                                  8
           elf_segment_alignment: 1 - 1
                                  ...
                                  2 - 2097152
                                  3 - 2097152
               elf_segment_flags: 1 - R--
                                  ...
                                  7 - RW-
    elf_segment_physical_address: 2 - 0
                                  7 - 0
                                  ...
                                  4 - 2226744
            elf_segment_sections: 0 -
                                  7 -
                                  ...
                                  5 - .note.ABI-tag, .note.gnu.build-id
                elf_segment_type: 4 - DYNAMIC
                                  6 - GNU_EH_FRAME
                                  ...
                                  0 - PHDR
     elf_segment_virtual_address: 2 - 0
                                  7 - 0
                                  ...
                                  4 - 2226744
        elf_segment_virtual_size: 7 - 0
                                  1 - 28
                                  ...
                                  2 - 124648
                        elf_type: DYN (Shared object file)

Feature key:
  elf_abi_version:  Version of the ABI to which the object is targeted
  elf_class:  Identifies the architecture
  elf_data:  Data encoding of the processor-specific data in the file
  elf_entrypoint:  Virtual address of the entry point
  elf_export:  Export name
  elf_export_binding:  Export binding attribute
  elf_export_size:  Export size
  elf_export_type:  Export type
  elf_export_value:  Export value
  elf_export_version:  Export version
  elf_export_visibility:  Export visibility
  elf_hdr_version:  Version number of the ELF specification
  elf_header_size:  ELF header size
  elf_import:  Import name
  elf_import_binding:  Import binding attribute
  elf_import_size:  Import size
  elf_import_type:  Import type
  elf_import_value:  Import value
  elf_import_version:  Import version
  elf_import_visibility:  Import visibility
  elf_machine:  Required architecture for the file
  elf_note:  Note index
  elf_note_abi:  Note ABI
  elf_note_description:  Description of the note
  elf_note_name:  Name of the note
  elf_note_type:  Type of the note
  elf_note_version:  Version of the note
  elf_num_prog_headers:  Number of entries in the program header table
  elf_num_section_headers:  Number of entries in the section header table
  elf_obj_version:  File version
  elf_os_abi:  Identifies the operating system and ABI
  elf_processor_flag:  Processor-specific flags
  elf_program_header_offset:  Program header table's file offset
  elf_program_header_size:  Program header table entry size
  elf_section:  Section name
  elf_section_alignment:  Section alignment
  elf_section_entropy:  Section entropy
  elf_section_entry_size:  Size of fixed-size entries
  elf_section_flags:  Flags that describe miscellaneous attributes
  elf_section_hash:  MD5 of the contents of the section
  elf_section_header_offset:  Section header table's file offset
  elf_section_header_size:  Section header entry size
  elf_section_information:  Extra information on the section
  elf_section_link:  Section header table index link
  elf_section_name_table_idx:  Section header string table index
  elf_section_num_flags:  Number of flags that describe miscellaneous section attributes
  elf_section_segments:  Segments associated with the given section
  elf_section_type:  Categorises the section's contents and semantics
  elf_section_virtual_address:  Address where the section will be mapped in memory
  elf_segment:  Number of segment in the file
  elf_segment_alignment:  The value to which the segments are aligned in memory and in the file.
  elf_segment_flags:  Segment’s flags
  elf_segment_physical_address:  Physical address of beginning of segment
  elf_segment_sections:  Sections inside this segment
  elf_segment_type:  Kind of segment described
  elf_segment_virtual_address:  Address where the segment will be mapped
  elf_segment_virtual_size:  Size of this segment in memory
  elf_type:  Object file type
```

Automated usage in system:

```
azul-fat-elf --server http://azul-dispatcher.localnet/
```

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
