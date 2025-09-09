import struct
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Type
import re


def _le_u16(b: bytes, off=0) -> int:
    return int.from_bytes(b[off:off+2], "little", signed=False)

def _le_i16(b: bytes, off=0) -> int:
    return int.from_bytes(b[off:off+2], "little", signed=True)

def _le_u32(b: bytes, off=0) -> int:
    return int.from_bytes(b[off:off+4], "little", signed=False)

def _le_i32(b: bytes, off=0) -> int:
    return int.from_bytes(b[off:off+4], "little", signed=True)

def _read_utf16le_z(b: bytes, off: int) -> str:
    if off < 0 or off >= len(b): return ""
    end = off
    while end + 1 < len(b):
        if b[end:end+2] == b"\x00\x00":
            break
        end += 2
    return b[off:end].decode("utf-16le", errors="ignore")

def _read_ascii_z(b: bytes, off: int) -> str:
    if off < 0 or off >= len(b): return ""
    end = b.find(b"\x00", off)
    if end == -1: end = len(b)
    return b[off:end].decode("latin-1", errors="ignore")

def _fmt_guid_le(b: bytes, off=0) -> str:
    """ Windows GUID(LE) 16바이트 -> 표준 문자열 """
    if off + 16 > len(b): return ""
    d1 = int.from_bytes(b[off:off+4], "little")
    d2 = int.from_bytes(b[off+4:off+6], "little")
    d3 = int.from_bytes(b[off+6:off+8], "little")
    d4 = b[off+8:off+10]
    d5 = b[off+10:off+16]
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4.hex().upper()}-{d5.hex().upper()}"


def _pascal_to_snake(name: str) -> str:
    name = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    name = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name)
    return name.lower()

EXTRA_DATA_SIGNATURE = {
    0xA0000002: "01_ConsoleDataBlock",
    0xA0000004: "02_ConsoleFEDataBlock",
    0xA0000006: "03_DarwinDataBlock",
    0xA0000001: "04_EnvironmentVariableDataBlock",
    0xA0000007: "05_IconEnvironmentDataBlock",
    0xA000000B: "06_KnownFolderDataBlock",
    0xA0000009: "07_PropertyStoreDataBlock",
    0xA0000008: "08_ShimDataBlock",
    0xA0000005: "09_SpecialFolderDataBlock",
    0xA0000003: "10_TrackerDataBlock",
    0xA000000C: "11_VistaAndAboveIDListDataBlock"
}

class BaseExtraBlock:
    def __init__(self, size: int, raw_bytes: bytes):
        self.size = size
        self.raw_bytes = raw_bytes
        self.readable = ""
        self.block_signature = None

    @staticmethod
    def _set_readable_unicode(raw_data):
        return raw_data.decode('utf-16').rstrip('\x00')

    @staticmethod
    def _set_readable_ansi(raw_data):
        return raw_data.decode('utf-8').rstrip('\x00')

    def __repr__(self):
        return self.readable

# 01_ConsoleDataBlock
class ConsoleDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        rb = self.raw_bytes
        self.block_signature = rb[0:4]
        self.fill_attributes = _le_u16(rb, 4)
        self.popup_fill_attributes = _le_u16(rb, 6)
        self.screen_buffer_size_x = _le_u16(rb, 8)
        self.screen_buffer_size_y = _le_u16(rb, 10)
        self.window_size_x = _le_u16(rb, 12)
        self.window_size_y = _le_u16(rb, 14)
        self.window_origin_x = _le_u16(rb, 16)
        self.window_origin_y = _le_u16(rb, 18)
        # unused: 4 + 4 -> 0x14..0x1B
        self.font_size = _le_u32(rb, 28)
        self.font_family = _le_u32(rb, 32)
        self.font_weight = _le_u32(rb, 36)
        self.face_name = rb[40:104].decode("utf-16le", errors="ignore").rstrip("\x00")
        self.cursor_size = _le_u32(rb, 104)
        self.full_screen = _le_u32(rb, 108)
        self.quick_edit = _le_u32(rb, 112)
        self.insert_mode = _le_u32(rb, 116)
        self.auto_position = _le_u32(rb, 120)
        self.history_buffer_size = _le_u32(rb, 124)
        self.number_of_history_buffers = _le_u32(rb, 128)
        self.history_no_dup = _le_u32(rb, 132)
        self.color_table = rb[136:200]  # 16 * RGBQUAD

        self.readable = (
            f"Console: Buf={self.screen_buffer_size_x}x{self.screen_buffer_size_y}, "
            f"Win={self.window_size_x}x{self.window_size_y}@({self.window_origin_x},{self.window_origin_y}), "
            f"Font(size={self.font_size}, family=0x{self.font_family:08X}, weight={self.font_weight}, face='{self.face_name}'), "
            f"Cursor={self.cursor_size}, QuickEdit={self.quick_edit}, Hist={self.history_buffer_size}x{self.number_of_history_buffers}"
        )

# 02_ConsoleFEDataBlock
class ConsoleFEDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        self.block_signature = self.raw_bytes[0:4]
        self.code_page = _le_u32(self.raw_bytes, 4)
        self.readable = f"ConsoleFE: CodePage={self.code_page}"

# 03_DarwinDataBlock
class DarwinDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        rb = self.raw_bytes
        self.block_signature = rb[0:4]
        self.darwin_data_ansi = rb[4:264]
        self.darwin_data_ansi_readable = self._set_readable_ansi(self.darwin_data_ansi)
        self.darwin_data_unicode = rb[264:784]
        self.darwin_data_unicode_readable = self._set_readable_unicode(self.darwin_data_unicode)
        self.readable = f"Darwin: A='{self.darwin_data_ansi_readable}', U='{self.darwin_data_unicode_readable}'"

class EnvironmentVariableDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        rb = self.raw_bytes
        self.block_signature = rb[0:4]
        self.target_ansi = rb[4:264]
        self.target_ansi_readable = self._set_readable_ansi(self.target_ansi)
        self.target_unicode = rb[264:784]
        self.target_unicode_readable = self._set_readable_unicode(self.target_unicode)
        self.readable = f"EnvVar: A='{self.target_ansi_readable}', U='{self.target_unicode_readable}'"

class IconEnvironmentDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        rb = self.raw_bytes
        self.block_signature = rb[0:4]
        self.target_ansi = rb[4:264]
        self.target_ansi_readable = self._set_readable_ansi(self.target_ansi)
        self.target_unicode = rb[264:784]
        self.target_unicode_readable = self._set_readable_unicode(self.target_unicode)
        self.readable = f"IconEnv: A='{self.target_ansi_readable}', U='{self.target_unicode_readable}'"

# 06_KnownFolderDataBlock
class KnownFolderDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        rb = self.raw_bytes
        self.block_signature = rb[0:4]
        self.known_folder_id = _fmt_guid_le(rb, 4)
        self.offset = _le_u32(rb, 20)
        self.readable = f"KnownFolder: KFID={self.known_folder_id}, Offset={self.offset}"

# 07_PropertyStoreDataBlock
class PropertyStoreDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        self.block_signature = self.raw_bytes[0:4]
        self.property_store = self.raw_bytes[4:]

        # ---- 최소 파서/힌트 ----
        # 1) UTF-16LE 문자열 후보 추출 (중복 제거)
        strings = []
        i = 0
        while i + 2 <= len(self.property_store):
            # 간단 휴리스틱: 0x00 0x00 종단을 가진 6바이트 이상 UTF-16 문자열
            if i + 6 <= len(self.property_store) and self.property_store[i:i+2] != b"\x00\x00":
                # 문자열 길이 상한(안전): 512바이트
                s = _read_utf16le_z(self.property_store, i)
                if s and len(s) >= 3:
                    strings.append(s)
                    i += (len(s.encode("utf-16le")) + 2)
                    continue
            i += 2
        uniq_strings = []
        seen = set()
        for s in strings:
            t = s.strip()
            if t and t not in seen:
                uniq_strings.append(t)
                seen.add(t)

        # 2) GUID 후보 추출
        guids = []
        for off in range(0, max(0, len(self.property_store) - 16) + 1):
            g = _fmt_guid_le(self.property_store, off)
            if g:
                guids.append(g)
        guids = list(dict.fromkeys(guids))  # uniq order

        self.strings = uniq_strings[:30]  # 너무 많으면 절단
        self.guids = guids[:30]

        self.readable = f"PropertyStore: strings={len(self.strings)}, guids={len(self.guids)}"

# 08_ShimDataBlock
class ShimDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        self.block_signature = self.raw_bytes[0:4]
        self.layer_name = self.raw_bytes[4:]
        self.layer_name_readable = self._set_readable_unicode(self.layer_name)

# 09_SpecialFolderDataBlock
class SpecialFolderDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        rb = self.raw_bytes
        self.block_signature = rb[0:4]
        self.special_folder_id = _le_u32(rb, 4)
        self.offset = _le_u32(rb, 8)
        self.readable = f"SpecialFolder: CSIDL={self.special_folder_id}, Offset={self.offset}"

# 10_TrackerDataBlock
class TrackerDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        rb = self.raw_bytes
        self.block_signature = rb[0:4]
        self.length = _le_u32(rb, 4)
        self.version = _le_u32(rb, 8)
        # MachineID: 16바이트 ANSI (널패딩) — 스펙에 따라 16 바이트
        self.machine_id_raw = rb[12:28]
        self.machine_id = self.machine_id_raw.split(b"\x00", 1)[0].decode("latin-1", errors="ignore")
        # Droid = Volume GUID(16) + File GUID(16)
        self.droid_volume = _fmt_guid_le(rb, 28)
        self.droid_file = _fmt_guid_le(rb, 44)
        # DroidBirth = Volume GUID(16) + File GUID(16)
        self.droid_birth_volume = _fmt_guid_le(rb, 60)
        self.droid_birth_file = _fmt_guid_le(rb, 76)

        self.mac_address = ":".join(self.droid_file.split("-")[-1][i:i+2] for i in range(0, len(self.droid_file.split("-")[-1]), 2))

        self.readable = (f"Tracker: Ver={self.version}, Len={self.length}, MachineID='{self.machine_id}', "
                         f"Vol={self.droid_volume}, File={self.droid_file}, "
                         f"BirthVol={self.droid_birth_volume}, BirthFile={self.droid_birth_file}")

# 11_VistaAndAboveIDListDataBlock
class VistaAndAboveIDListDataBlock(BaseExtraBlock):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)
        self.block_signature = self.raw_bytes[0:4]
        self.id_list = self.raw_bytes[4:]
        # 가독 힌트: SHITEMID 개수 추정
        cnt = 0; off = 0
        while off + 2 <= len(self.id_list):
            sz = _le_u16(self.id_list, off)
            if sz == 0:
                break
            if sz < 2 or off + sz > len(self.id_list):
                break
            cnt += 1
            off += sz
        self.readable = f"Vista+ IDList: {cnt} items, bytes={len(self.id_list)}"

@dataclass
class ExtraData:
    console_data_block: List[ConsoleDataBlock] = field(default_factory=list)
    console_fe_data_block: List[ConsoleFEDataBlock] = field(default_factory=list)
    darwin_data_block: List[DarwinDataBlock] = field(default_factory=list)
    environment_variable_data_block: List[EnvironmentVariableDataBlock] = field(default_factory=list)
    icon_environment_data_block: List[IconEnvironmentDataBlock] = field(default_factory=list)
    known_folder_data_block: List[KnownFolderDataBlock] = field(default_factory=list)
    property_store_data_block: List[PropertyStoreDataBlock] = field(default_factory=list)
    shim_data_block: List[ShimDataBlock] = field(default_factory=list)
    special_folder_data_block: List[SpecialFolderDataBlock] = field(default_factory=list)
    tracker_data_block: List[TrackerDataBlock] = field(default_factory=list)
    vista_and_above_id_list_data_block: List[VistaAndAboveIDListDataBlock] = field(default_factory=list)

    def add_block(self, flag: str, block: BaseExtraBlock):
        attr_name = _pascal_to_snake(flag.split("_", 1)[1])  # "console_data_block"
        lst = getattr(self, attr_name, None)
        if lst is not None:
            lst.append(block)

    @staticmethod
    def notionable(cls):
        blocks = []

        if len(cls.console_data_block) > 0:
            blocks.append("01_ConsoleDataBlock")
        if len(cls.console_fe_data_block) > 0:
            blocks.append("02_ConsoleFEDataBlock")
        if len(cls.darwin_data_block) > 0:
            blocks.append("03_DarwinDataBlock")
        if len(cls.environment_variable_data_block) > 0:
            blocks.append("04_EnvironmentVariableDataBlock")
        if len(cls.icon_environment_data_block) > 0:
            blocks.append("05_IconEnvironmentDataBlock")
        if len(cls.known_folder_data_block) > 0:
            blocks.append("06_KnownFolderDataBlock")
        if len(cls.property_store_data_block) > 0:
            blocks.append("07_PropertyStoreDataBlock")
        if len(cls.shim_data_block) > 0:
            blocks.append("08_ShimDataBlock")
        if len(cls.special_folder_data_block) > 0:
            blocks.append("09_SpecialFolderDataBlock")
        if len(cls.tracker_data_block) > 0:
            blocks.append("10_TrackerDataBlock")
        if  len(cls.vista_and_above_id_list_data_block) > 0:
            blocks.append("11_VistaAndAboveIDListDataBlock")

        tracker = cls.tracker_data_block[0]

        result = {
            "DataBlocks": blocks,
            "MachineID": tracker.machine_id,
            "MacAddress": tracker.mac_address,
            "FileDroid": tracker.droid_file,
            "VolumeDroid": tracker.droid_volume,
            "FileDroidBirth": tracker.droid_birth_file,
            "VolumeDroidBirth": tracker.droid_birth_volume,
        }
        return result

def __check_signature(signature: bytes) -> str:
    flags, = struct.unpack("<I", signature)
    return EXTRA_DATA_SIGNATURE.get(flags, "UNKNOWN")

def check_signature(block_size: int, raw_data_block: bytes) -> Tuple[str, Optional[BaseExtraBlock]]:
    block = __check_signature(raw_data_block[0:4])
    mapping: Dict[str, Type[BaseExtraBlock]] = {
        "01_ConsoleDataBlock": ConsoleDataBlock,
        "02_ConsoleFEDataBlock": ConsoleFEDataBlock,
        "03_DarwinDataBlock": DarwinDataBlock,
        "04_EnvironmentVariableDataBlock": EnvironmentVariableDataBlock,
        "05_IconEnvironmentDataBlock": IconEnvironmentDataBlock,
        "06_KnownFolderDataBlock": KnownFolderDataBlock,
        "07_PropertyStoreDataBlock": PropertyStoreDataBlock,
        "08_ShimDataBlock": ShimDataBlock,
        "09_SpecialFolderDataBlock": SpecialFolderDataBlock,
        "10_TrackerDataBlock": TrackerDataBlock,
        "11_VistaAndAboveIDListDataBlock": VistaAndAboveIDListDataBlock,
    }
    return block, mapping.get(block, BaseExtraBlock)(block_size, raw_data_block) if block in mapping else None
