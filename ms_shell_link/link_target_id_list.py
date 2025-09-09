from utils import read_guid, dos_datetime_to_str
from enum import IntEnum, IntFlag

class SortIndex(IntEnum):
    DESKTOP = 0x00
    INTERNET_EXPLORER = 0x01
    LIBRARIES = 0x1A
    CONTROL_PANEL = 0x20
    PRINTERS = 0x40
    NETWORK = 0x42
    RECYCLE_BIN = 0x44
    PERSONAL = 0x48
    MY_COMPUTER = 0x50
    MY_MUSIC = 0x58
    MY_VIDEOS = 0x60

class FileAttributes(IntFlag):
    READONLY            = 0x00000001
    HIDDEN              = 0x00000002
    SYSTEM              = 0x00000004
    VOLUME_LABEL        = 0x00000008
    DIRECTORY           = 0x00000010
    ARCHIVE             = 0x00000020
    NORMAL              = 0x00000080
    TEMPORARY           = 0x00000100
    SPARSE_FILE         = 0x00000200
    REPARSE_POINT       = 0x00000400
    COMPRESSED          = 0x00000800
    OFFLINE             = 0x00001000
    NOT_CONTENT_INDEXED = 0x00002000
    ENCRYPTED           = 0x00004000

class PrimaryName:
    def __init__(self, data):
        end = data.find(b'\x00')

        if end == -1:
            self.value = ""
        else:
            self.value = data[:end].decode("utf-8")
            self.size = end + 1

    def __repr__(self):
        return self.value

class DosDateTime:
    def __init__(self, data):
        self.date = data[:2]
        self.time = data[2:4]
        self.readable = dos_datetime_to_str(data)

    def __repr__(self):
        return self.readable

def set_hex(data):
    value = int.from_bytes(data, 'little')
    return f"0x{value:08X}".rstrip("00")

class FileReference:
    def __init__(self, data):
        self.mft_entry = set_hex(data[:4])
        self.sequence = set_hex(data[4:8])

    def __repr__(self):
        return f"{self.mft_entry} / {self.sequence}"

    def value(self):
        return f"{self.mft_entry} / {self.sequence}"

class ExtraDataBlock:
    def __init__(self, data, str_size):
        size = data[0:2]
        self.size = int.from_bytes(size, 'little')
        self.version = int.from_bytes(data[2:4], 'little')
        self.signature = set_hex(data[4:8])
        self.created_time = DosDateTime(data[8:12])
        self.accessed_time = DosDateTime(data[12:16])
        self.identifier = int.from_bytes(data[16:18], 'little')
        self.file_reference = FileReference(data[20:28])
        self.long_string_size = int.from_bytes(data[36:38], 'little')

        offset = 38 + 8
        name_size = offset + (str_size * 2)
        self.name = data[offset: name_size].decode("utf-16").strip('\x00')
        self.version_offset = int.from_bytes(data[name_size:], 'little')

class IDList:
    def __init__(self, size, raw):
        self.size = size
        self.raw = raw[2:]
        self._parse()

    def _parse(self):
        self.type_data = self.raw[0:1]

        if self.type_data[0] == 0x1F:
            # Root
            self.type = "ROOT"
            self.sort_index = SortIndex(self.raw[1:2][0]).name
            self.clsid = read_guid(self.raw[2:])
        elif self.type_data[0] == 0x2f:
            # Volume
            self.type = "VOLUME"
            self.name = self.raw[1:]
            self.readable = self.name.rstrip(b"\x00")
        elif self.type_data[0] == 0x31 or self.type_data[0] == 0x32:
            self.type = "DIRECTORY" if self.type_data[0] == 0x31 else "FILE"
            self.file_size = int.from_bytes(self.raw[2:6], 'little')
            self.modified_time = DosDateTime(self.raw[6:10])
            self.file_attributes = FileAttributes(self.raw[10:12][0]).name
            self.primary_name = PrimaryName(self.raw[12:])

            extra_start = 12 if self.primary_name.size % 2 == 0 else 13
            self.extra_data = ExtraDataBlock(self.raw[extra_start + self.primary_name.size:], self.primary_name.size)

class LinkTargetIDList:
    def __init__(self, size, raw):
        self.size = size
        self.raw_data = raw
        self.array_id_list = []

        self._parse_id_list()

    def _parse_id_list(self):
        offset = 0
        for _ in range(0, self.size):
            if self.size - offset == 2:
                break

            size = self.raw_data[offset: offset + 2]
            int_size = int.from_bytes(size, "little")
            data = self.raw_data[offset: offset + int_size]

            id_list = IDList(int_size, data)
            self.array_id_list.append(id_list)
            offset += int_size

    @staticmethod
    def notionable(data):
        ids = data.array_id_list
        id_list = []

        name = ["CLSID_" + ids[0].sort_index, ids[1].readable.decode('utf-8')]

        for i in range(2, len(ids)):
            name.append(ids[i].primary_name.value)
            item = {
                "IDLIST": ids[i].primary_name.value,
                "MFT_ENTRY_Sequence_Number": ids[i].extra_data.file_reference.value(),
                "CreateTime": ids[i].extra_data.created_time.readable,
                "AccessTime": ids[i].extra_data.accessed_time.readable,
                "ModifiedTime": ids[i].modified_time.readable,
            }
            id_list.append(item)

        name = r'\\'.join(name)

        return {
            "sListTargetIDList": name,
            "IDLIST": id_list
        }

