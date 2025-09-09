
class BaseStringData:
    def __init__(self, size: int, raw_bytes: bytes):
        self.size = size
        self.unicode_size = size * 2
        self.raw_bytes = raw_bytes
        self.readable = ""
        self._set_readable()

    def _set_readable(self):
        self.readable = self.raw_bytes.decode('utf-16').strip('\x00')
        self.readable = self.readable.split('\x00')[0]

    def __repr__(self):
        return self.readable

class NameString(BaseStringData):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)

class RelativePath(BaseStringData):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)

class WorkingDir(BaseStringData):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)

class CommandLineArguments(BaseStringData):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)

class IconLocation(BaseStringData):
    def __init__(self, size: int, raw_bytes: bytes):
        super().__init__(size, raw_bytes)

class StringData:
    def __init__(self):
        self.icon_location = None
        self.command_line_arguments = None
        self.working_dir = None
        self.relative_path = None
        self.name_string = None

    def set_name_string(self, name_string: NameString):
        self.name_string = name_string

    def set_relative_path(self, relative_path: RelativePath):
        self.relative_path = relative_path

    def set_working_dir(self, working_dir: WorkingDir):
        self.working_dir = working_dir

    def set_command_line_arguments(self, command_line_arguments: CommandLineArguments):
        self.command_line_arguments = command_line_arguments

    def set_icon_location(self, icon_location: IconLocation):
        self.icon_location = icon_location

    @staticmethod
    def notionable(data):
        return {
            "NameString": data.name_string,
            "RELATIVE_PATH": data.relative_path.readable,
            "WORKING_DIR": data.working_dir.readable if data.working_dir else "",
            "COMMAND_LINE_ARGUMENTS": data.command_line_arguments.readable,
            "ICON_LOCATION": data.icon_location.readable,
        }
