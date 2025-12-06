# Copyright (C) 2024 enzok
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import struct
from typing import List

import pefile
import yara

log = logging.getLogger(__name__)

DESCRIPTION = "NitroBunnyDownloader configuration parser."
AUTHOR = "enzok"

yara_rule = """
rule NitroBunnyDownloader
{
    meta:
        author = "enzok"
        description = "NitroBunnyDownloader Payload"
        cape_type = "NitroBunnyDownloader Payload"
        hash = "960e59200ec0a4b5fb3b44e6da763f5fec4092997975140797d4eec491de411b"
    strings:
        $config1 = {E8 [3] 00 41 B8 ?? ?? 00 00 48 8D 15 [3] 00 48 89 C1 4? 89 ?? E8 [3] 00}
        $config2 = {E8 [3] 00 48 8D 15 [3] 00 41 B8 ?? ?? 00 00 48 89 C1 4? 89 ?? E8 [3] 00}
        $string1 = "X-Amz-User-Agent:" wide
        $string2 = "Amz-Security-Flag:" wide
        $string3 = "/cart" wide
        $string4 = "Cookie: " wide
        $string5 = "wishlist" wide
    condition:
        uint16(0) == 0x5A4D and 1 of ($config*) and 2 of ($string*)
}
"""

yara_rules = yara.compile(source=yara_rule)


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except Exception as e:
        print(e)
        return None


def read_dword(data, off):
    if off + 4 > len(data):
        raise ValueError(f"EOF reading dword at {off}")
    val = struct.unpack_from("<I", data, off)[0]
    return val, off + 4


def read_qword(data, off):
    """Read a 64-bit unsigned little-endian value."""
    if off + 8 > len(data):
        raise ValueError(f"EOF reading qword at {off}")
    val = struct.unpack_from("<Q", data, off)[0]
    return val, off + 8


def read_utf16le_string(data, off, length):
    if off + length > len(data):
        raise ValueError(f"EOF reading string at {off} len={length}")
    raw = data[off:off + length]
    s = raw.decode("utf-16le", errors="replace").rstrip("\x00")
    return s, off + length


def read_string_list(data, off, count):
    items = []
    for i in range(count):
        length_words, off = read_qword(data, off)
        s, off = read_utf16le_string(data, off, length_words)
        items.append(s)
    return items, off


def make_endpoints(cncs: List[str], port: int, uris: List[str]) -> List[str]:
    endpoints = []
    schema = {80: "http", 443: "https"}.get(port, "tcp")
    for cnc in cncs:
        base_url = f"{schema}://{cnc}"
        if port not in (80, 443):
            base_url += f":{port}"

        for uri in uris:
            endpoints.append(f"{base_url}/{uri.lstrip('/')}")

    return endpoints


def extract_config(filebuf):
    yara_hit = yara_scan(filebuf)
    if not yara_hit:
        return None

    cfg = {}
    config_code_offset = None
    config_size_offset = None
    config_offset = None
    rva_offset = None

    CONFIG_OFFSETS = {
        "$config1": (7, 14, 18),
        "$config2": (14, 8, 12),
    }

    for hit in yara_hit:
        if hit.rule != "NitroBunnyDownloader":
            continue

        for item in hit.strings:
            if item.identifier in CONFIG_OFFSETS and item.instances:
                config_code_offset = item.instances[0].offset
                config_size_offset, config_offset, rva_offset = CONFIG_OFFSETS[item.identifier]
                break

            if config_code_offset:
                break

    if config_code_offset is None:
        return None

    try:
        pe = pefile.PE(data=filebuf, fast_load=True)
        config_length = pe.get_dword_from_offset(config_code_offset + config_size_offset)
        config_data_offset = pe.get_dword_from_offset(config_code_offset + config_offset)
        rva = pe.get_rva_from_offset(config_code_offset + rva_offset)
        config_rva = rva + config_data_offset
        data = pe.get_data(config_rva, config_length)
        off = 0
        cfg["CNCs"] = []
        port, off = read_dword(data, off)
        num, off = read_dword(data, off)
        cncs, off = read_string_list(data, off, num)
        num, off = read_qword(data, off)
        cfg["user_agent"], off = read_utf16le_string(data, off, num)
        num, off = read_dword(data, off)
        raw = cfg["raw"] = {}
        raw["http_header_items"], off = read_string_list(data, off, num)
        num, off = read_dword(data, off)
        uris, off = read_string_list(data, off, num)
        raw["unknown_1"], off = read_dword(data, off)
        raw["unknown_2"], off = read_dword(data, off)
        if cncs:
            cfg["CNCs"] = make_endpoints(cncs, port, uris)

    except Exception as e:
        log.error("Error: %s", e)
        return None

    return cfg


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))

detection_rule = """
rule NitroBunnyDownloader
{
    meta:
        author = "enzok"
        description = "NitroBunnyDownloader"
        cape_type = "NitroBunnyDownloader Payload"
        hash = "960e59200ec0a4b5fb3b44e6da763f5fec4092997975140797d4eec491de411b"
    strings:
        $config1 = {E8 [3] 00 41 B8 ?? ?? 00 00 48 8D 15 [3] 00 48 89 C1 48 89 ?? E8 [3] 00}
        $config2 = {E8 [3] 00 48 8D 15 [3] 00 41 B8 ?? ?? 00 00 48 89 C1 48 89 ?? E8 [3] 00}
        $string1 = "X-Amz-User-Agent:" wide
        $string2 = "Amz-Security-Flag:" wide
        $string3 = "/cart" wide
        $string4 = "Cookie: " wide
        $string5 = "wishlist" wide
    condition:
        uint16(0) == 0x5A4D and 1 of ($config*) and 2 of ($string*)
}

"""
