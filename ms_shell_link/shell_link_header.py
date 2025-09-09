from utils import windows_filetime_to_str
import struct

LINK_FLAGS = {
    0x00000001: "01_HasLinkTargetIDList",
    0x00000002: "02_HasLinkInfo",
    0x00000004: "03_HasName",
    0x00000008: "04_HasRelativePath",
    0x00000010: "05_HasWorkingDir",
    0x00000020: "06_HasArguments",
    0x00000040: "07_HasIconLocation",
    0x00000080: "08_IsUnicode",
    0x00000100: "09_ForceNoLinkInfo",
    0x00000200: "10_HasExpString",
    0x00000400: "11_RunInSeparateProcess",
    0x00002000: "12_HasDarwinID",
    0x00004000: "13_RunAsUser",
    0x00008000: "14_HasExpIcon",
    0x00010000: "15_NoPidlAlias",
    0x00020000: "16_RunWithShimLayer",
    0x00040000: "17_ForceNoLinkTrack",
    0x00080000: "18_EnableTargetMetadata",
    0x00100000: "19_DisableLinkPathTracking",
    0x00200000: "20_DisableKnownFolderTracking",
    0x00400000: "21_DisableKnownFolderAlias",
    0x00800000: "22_AllowLinkToLink",
    0x01000000: "23_UnaliasOnSave",
    0x02000000: "24_PreferEnvironmentPath",
    0x04000000: "25_KeepLocalIDListForUNCTarget"
}

FILE_ATTRIBUTES_FLAGS = {
    0x00000001: "FILE_ATTRIBUTE_READONLY",
    0x00000002: "FILE_ATTRIBUTE_HIDDEN",
    0x00000004: "FILE_ATTRIBUTE_SYSTEM",
    0x00000010: "FILE_ATTRIBUTE_DIRECTORY",
    0x00000020: "FILE_ATTRIBUTE_ARCHIVE",
    0x00000080: "FILE_ATTRIBUTE_NORMAL",
    0x00000100: "FILE_ATTRIBUTE_TEMPORARY",
    0x00000200: "FILE_ATTRIBUTE_SPARSE_FILE",
    0x00000400: "FILE_ATTRIBUTE_REPARSE_POINT",
    0x00000800: "FILE_ATTRIBUTE_COMPRESSED",
    0x00001000: "FILE_ATTRIBUTE_OFFLINE",
    0x00002000: "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED",
    0x00004000: "FILE_ATTRIBUTE_ENCRYPTED"
}

SHOW_COMMAND = {
    0x00000001: "SW_SHOWNORMAL (1)",
    0x00000003: "SW_SHOWMAXIMIZED(3)",
    0x00000007: "SW_SHOWMINNOACTIVE (7)"
}

class ShellLinkHeader:
    CLSID_MUST = "00021401-0000-0000-C000-000000000046"

    def __init__(self, raw_bytes: bytes):
        self.raw = raw_bytes
        self.signature: bytes | None = None
        self.clsid: bytes | None = None
        self.link_flags: bytes | None = None
        self.file_attributes: bytes | None = None
        self.creation_time: bytes | None = None
        self.access_time: bytes | None = None
        self.write_time: bytes | None = None
        self.file_size: bytes | None = None
        self.icon_index: bytes | None = None
        self.show_command: bytes | None = None
        self.hot_key: bytes | None = None
        self.reserved: bytes | None = None
        self.ct_readable: str | None = None
        self.at_readable: str | None = None
        self.wt_readable: str | None = None

        self._parse()

    def _parse(self) -> None:
        self.signature = self.raw[0:4]
        self.clsid = self.raw[4:20]

        self.link_flags = self.raw[20:24]
        self._get_link_flags()

        self.file_attributes = self.raw[24:28]
        self._get_file_attributes()

        self.creation_time = self.raw[28:36]
        self.ct_readable = windows_filetime_to_str(self.creation_time)

        self.access_time = self.raw[36:44]
        self.at_readable = windows_filetime_to_str(self.access_time)

        self.write_time = self.raw[44:52]
        self.wt_readable = windows_filetime_to_str(self.write_time)

        self.file_size = self.raw[52:56]
        self.file_size_readable = int.from_bytes(self.file_size, 'little')

        self.icon_index = self.raw[56:60]
        self.icon_index_readable = int.from_bytes(self.icon_index, "little")

        self.show_command = self.raw[60:64]
        self._get_show_command()
        self.hot_key = self.raw[64:66]
        self.reserved = self.raw[66:]

    def _get_link_flags(self):
        flags, = struct.unpack("<I", self.link_flags)
        results = [name for bit, name in LINK_FLAGS.items() if flags & bit]
        self.link_flags_readable = results

    def _get_file_attributes(self):
        flags, = struct.unpack("<I", self.file_attributes)
        results = [name for bit, name in FILE_ATTRIBUTES_FLAGS.items() if flags & bit]
        self.file_attributes_readable = results

    def _get_show_command(self):
        flags, = struct.unpack("<I", self.show_command)
        self.show_command_readable = SHOW_COMMAND.get(flags, "UNKNOWN")

    @staticmethod
    def notionable(header):

        result = {
            "LinkFlags": header.link_flags_readable,
            "FileAttributes": header.file_attributes_readable[0],
            "CreationTime": header.ct_readable,
            "AccessTime": header.at_readable,
            "WriteTime": header.wt_readable,
            "FileSize": header.file_size_readable,
            "IconIndex": header.icon_index_readable,
            "ShowCommand": header.show_command_readable,
        }

        return result