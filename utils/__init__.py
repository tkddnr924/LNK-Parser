from datetime import datetime, timezone, timedelta
from typing import Union, Optional
import struct

_BASE_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

def windows_filetime_to_str(v: Union[int, bytes, bytearray]) -> str:
    ft = (
        int.from_bytes(v, "little", signed=False)
        if isinstance(v, (bytes, bytearray))
        else int(v)
    )
    if ft <= 0:
        return "1601-01-01 00:00:00.000000"
    dt = _BASE_EPOCH + timedelta(microseconds=ft // 10)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")

def dos_datetime_to_str(hex_bytes: bytes):
    dos_date, dos_time  = struct.unpack("<HH", hex_bytes)
    sec = (dos_time & 0x1F) * 2
    minute = (dos_time >> 5) & 0x3F
    hour = (dos_time >> 11) & 0x1F
    day = dos_date & 0x1F
    month = (dos_date >> 5) & 0x0F
    year = ((dos_date >> 9) & 0x7F) + 1980
    return datetime(year, month, day, hour, minute, sec).strftime("%Y-%m-%d %H:%M:%S")

def read_guid(b: bytes, off: int = 0) -> Optional[str]:
    if len(b) < off + 16:
        return None
    d1 = int.from_bytes(b[off:off+4], "little")
    d2 = int.from_bytes(b[off+4:off+6], "little")
    d3 = int.from_bytes(b[off+6:off+8], "little")
    d4 = b[off+8:off+10]  # 2 bytes
    d5 = b[off+10:off+16] # 6 bytes
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4.hex().upper()}-{d5.hex().upper()}"

def _empty(x): return '' if x in (None, '', [], {}, ()) else x