from .shell_link_header import ShellLinkHeader
from .string_data import StringData, NameString, RelativePath, WorkingDir, CommandLineArguments, IconLocation
from .extra_data import ExtraData, check_signature
from .link_target_id_list import LinkTargetIDList
from .link_info import LinkInfo
import hashlib
import os

def _dump_list(title, lst, limit=3):
    if not lst: return
    print(f"\t[{title}]")
    for i, blk in enumerate(lst[:limit], 1):
        print(f"\t  ({i}) {blk.readable}")

class LNKStructure:
    def __init__(self, path):
        self.string_data = None
        self.header : ShellLinkHeader = None
        self.file_path = path
        self.file_size = os.path.getsize(path)

        with open(path, "rb") as f:
            file_data = f.read()
            self.md5 = hashlib.md5(file_data).hexdigest()
            self.sha1 = hashlib.sha1(file_data).hexdigest()
            self.sha256 = hashlib.sha256(file_data).hexdigest()

        self._parse()

    def get_notion_data(self):
        header = ShellLinkHeader.notionable(self.header)
        id_list = LinkTargetIDList.notionable(self.link_target_id_list)
        link_info = LinkInfo.notionable(self.link_info)
        string_data = StringData.notionable(self.string_data)
        ex_data = ExtraData.notionable(self.extra_data)

        return {
            "ShellLinkHeader": header,
            "LinkTargetIDList": id_list,
            "LinkInfo": link_info,
            "StringData": string_data,
            "ExtraData": ex_data,
        }


    def _parse(self):
        with open(self.file_path, "rb") as _file:
            header_size = 76
            header = _file.read(header_size)
            self.header = ShellLinkHeader(header)

            link_flags = self.header.link_flags_readable

            if "01_HasLinkTargetIDList" in link_flags:
                list_size_raw = _file.read(2)
                id_list_size = int.from_bytes(list_size_raw, "little")
                id_list_data = _file.read(id_list_size)

                self.link_target_id_list = LinkTargetIDList(id_list_size, id_list_data)

            if "02_HasLinkInfo" in link_flags:
                info_size = _file.read(4)
                link_info_size = int.from_bytes(info_size, "little")
                link_info_data = _file.read(link_info_size - 4)
                self.link_info = LinkInfo(link_info_size, link_info_data)

            # string data
            self.string_data = StringData()

            if "03_HasName" in link_flags:
                string_size_raw = _file.read(2)
                string_size = int.from_bytes(string_size_raw, "little")
                string_data = _file.read(string_size * 2)  # unicode
                ns = NameString(string_size, string_data)
                self.string_data.set_name_string(ns)

            if "04_HasRelativePath" in link_flags:
                string_size_raw = _file.read(2)
                string_size = int.from_bytes(string_size_raw, "little")
                string_data = _file.read(string_size * 2)  # unicode
                rp = RelativePath(string_size, string_data)
                self.string_data.set_relative_path(rp)

            if "05_HasWorkingDir" in link_flags:
                string_size_raw = _file.read(2)
                string_size = int.from_bytes(string_size_raw, "little")
                string_data = _file.read(string_size * 2)  # unicode
                wd = WorkingDir(string_size, string_data)
                self.string_data.set_working_dir(wd)

            if "06_HasArguments" in link_flags:
                string_size_raw = _file.read(2)
                string_size = int.from_bytes(string_size_raw, "little")
                string_data = _file.read(string_size * 2)
                cla = CommandLineArguments(string_size, string_data)
                self.string_data.set_command_line_arguments(cla)

            if "07_HasIconLocation" in link_flags:
                string_size_raw = _file.read(2)
                string_size = int.from_bytes(string_size_raw, "little")
                string_data = _file.read(string_size * 2)
                il = IconLocation(string_size, string_data)
                self.string_data.set_icon_location(il)

            # Extra Data
            self.extra_data = ExtraData()

            while True:
                extra_size = _file.read(4)
                if len(extra_size) < 4:
                    break
                block_size = int.from_bytes(extra_size, 'little')

                if block_size < 1:
                    break

                block_data = _file.read(block_size - 4)
                flag, block = check_signature(block_size, block_data)

                if flag == "UNKNOWN":
                    break

                self.extra_data.add_block(flag, block)
