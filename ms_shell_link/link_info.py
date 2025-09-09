from enum import IntEnum

class DriveType(IntEnum):
    DRIVE_UNKNOWN       = 0x00000000
    DRIVE_NO_ROOT_DIR   = 0x00000001
    DRIVE_REMOVABLE     = 0x00000002
    DRIVE_FIXED         = 0x00000003
    DRIVE_REMOTE        = 0x00000004
    DRIVE_CDROM         = 0x00000005
    DRIVE_RAMDISK       = 0x00000006

def hex_to_swapped_string(data: bytes) -> str:
    # 2바이트 단위로 잘라서 리틀엔디언 → 빅엔디언으로 바꿔줌
    words = []
    for i in range(0, len(data), 2):
        w = int.from_bytes(data[i:i+2], "little")
        words.append(f"{w:04X}")
    return "-".join(words)

class VolumeID:
    def __init__(self, raw):
        self.raw = raw

        self.size = int.from_bytes(raw[0:4], 'little')
        self.driver_type = DriveType(raw[4:8][0]).name
        self.driver_serial_number = hex_to_swapped_string(raw[8:12])
        self.volume_label_offset = raw[12:16]

class LinkInfoFlags:
    def __init__(self, raw):
        int_bytes = int.from_bytes(raw, "little")
        self.volume_id_and_base_path = bool(int_bytes & 0x00000001)
        self.common_network = bool(int_bytes & 0x00000002)

class LinkInfo:
    def __init__(self, size, data):
        self.size = size
        self.raw_data = data

        self.__parse_lnk_info()

    def __parse_lnk_info(self):
        self.link_info_header_size = int.from_bytes(self.raw_data[0:4], 'little')
        self.link_info_flags = LinkInfoFlags(self.raw_data[4:8])
        self.volume_id_offset = int.from_bytes(self.raw_data[8:12], 'little')
        self.local_base_path_offset = int.from_bytes(self.raw_data[12:16], 'little')
        self.common_network_relative_link_offset = int.from_bytes(self.raw_data[16:20], 'little')
        self.common_path_suffix_offset = int.from_bytes(self.raw_data[20:24], 'little')

        volume_id_offset = self.volume_id_offset - 4
        local_base_path_offset = self.local_base_path_offset - 4
        common_network_relative_offset = self.common_network_relative_link_offset - 4
        common_path_suffix_offset = self.common_path_suffix_offset - 4

        if self.link_info_flags.volume_id_and_base_path:
            volume_id_size = local_base_path_offset - volume_id_offset
            local_base_size = (common_network_relative_offset if self.link_info_flags.common_network else common_path_suffix_offset) - local_base_path_offset

            self.volume_id = VolumeID(self.raw_data[volume_id_offset: volume_id_offset + volume_id_size])
            self.local_base_path = self.raw_data[local_base_path_offset: local_base_path_offset + local_base_size ]
            self.local_base_path = self.local_base_path.decode("utf-8").rstrip("\x00")

    @staticmethod
    def notionable(data):
        return {
            "DriveType": data.volume_id.driver_type,
            "DriveSerialNumber": data.volume_id.driver_serial_number,
            "Data": "",
            "LocalBasePath": data.local_base_path,
        }
