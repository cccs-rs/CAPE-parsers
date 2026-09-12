import base64
import logging
import re
import struct
from contextlib import suppress
from io import BytesIO

import pefile
import yara

rule_source = """
rule PikaBot
{
    meta:
        author = "enzo"
        description = "Pikabot config extraction"
        packed = ""
    strings:
        $config = {C7 44 24 [3] 00 00 C7 44 24 [4] 00 89 [1-4] ?? E8 [4] 31 C0 C7 44 24 [3] 00 00 89 44 24 ?? C7 04 24 [4] E8}
    condition:
        uint16(0) == 0x5A4D and all of them
}
"""

yara_rules = yara.compile(source=rule_source)

log = logging.getLogger(__name__)


class PikaException(Exception):
    pass


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except Exception as e:
        print(e)


def xor(data, key):
    return bytes([c ^ key for c in data])


def wide_finder(data):
    str_end = len(data)
    for i in range(0, len(data) - 1, 2):
        if not chr(data[i]).isascii():
            str_end = i
            break
        if data[i + 1] != 0:
            str_end = i
            break
    return data[:str_end]


def get_url(ps_string):
    out = None
    m = re.search(r"http[^ ]*", ps_string)
    if m:
        out = m.group()
    return out


def get_wchar_string(data, length):
    data = data.read(length)
    return data.decode("utf-16-le")


def get_strings(data, count):
    w_strings = []
    for _ in range(count):
        length = struct.unpack("I", data.read(4))[0]
        w_string = get_wchar_string(data, length)
        w_strings.append(w_string)
    return w_strings


def get_c2s(data, count):
    c2_list = []
    for _ in range(count):
        c2_size = struct.unpack("I", data.read(4))[0]
        c2 = get_wchar_string(data, c2_size)
        port, val1, val2 = struct.unpack("III", data.read(12))
        c2_list.append(f"http://{c2}:{port}")
    return c2_list


def get_config(input_data):
    data = BytesIO(input_data)
    rounds, config_size, _, version_size = struct.unpack("=IIBI", data.read(13))
    version = get_wchar_string(data, version_size)
    campaign_size = struct.unpack("I", data.read(4))[0]
    campaign_name = get_wchar_string(data, campaign_size)
    registry_key_size = struct.unpack("I", data.read(4))[0]
    registry_key = get_wchar_string(data, registry_key_size)
    user_agent_size = struct.unpack("I", data.read(4))[0]
    user_agent = get_wchar_string(data, user_agent_size)
    number_of_http_headers = struct.unpack("I", data.read(4))[0]
    get_strings(data, number_of_http_headers)
    number_of_api_cmds = struct.unpack("I", data.read(4))[0]
    get_strings(data, number_of_api_cmds)
    number_of_c2s = struct.unpack("I", data.read(4))[0]
    c2s = get_c2s(data, number_of_c2s)

    return {
        "version": version,
        "campaign": campaign_name,
        "raw": {"Registry Key": registry_key},
        "user_agent": user_agent,
        # "request_headers": request_headers,
        # "api_cmds": api_cmds,
        "CNCs": c2s,
    }


def extract_config(filebuf):
    pe = None
    with suppress(Exception):
        pe = pefile.PE(data=filebuf, fast_load=False)

    if not pe:
        return

    r_data = None
    data = None

    r_data_sections = [s for s in pe.sections if s.Name.find(b".rdata") != -1]
    if r_data_sections:
        r_data = r_data_sections[0].get_data()

    data_sections = [s for s in pe.sections if s.Name.find(b".data") != -1]
    if data_sections:
        data = data_sections[0].get_data()

    if r_data:
        big_null = r_data.find(b"\x00" * 30)
        r_data = r_data[:big_null]
        out = None

        for i in range(1, 0xFF):
            egg = bytes([i]) * 16
            if egg in r_data:
                test_out = xor(r_data, i)
                # This might break if the extra crud on the end of the blob is not b64 friendly
                try:
                    test_out_ptxt = base64.b64decode(test_out)
                except Exception:
                    continue
                if "http".encode("utf-16le") in test_out_ptxt:
                    out = wide_finder(test_out_ptxt).decode("utf-16le")
        if out:
            url = get_url(out)
            return {"CNCs": [url], "raw": {"PowerShell": out}}

    if data:
        yara_hit = yara_scan(filebuf)
        cfg_va = None
        cfg_offset = None
        cfg_length = 0

        for hit in yara_hit:
            if hit.rule == "PikaBot":
                for item in hit.strings:
                    if "$config" == item.identifier:
                        offset = item.instances[0].offset
                        cfg_va = filebuf[offset + 12 : offset + 16]
                with suppress(Exception):
                    pe = pefile.PE(data=filebuf, fast_load=True)
                    cfg_offset = pe.get_offset_from_rva(struct.unpack("I", cfg_va)[0] - pe.OPTIONAL_HEADER.ImageBase)
                    cfg_length = struct.unpack("H", filebuf[offset + 4 : offset + 6])[0]
                    break

        if cfg_offset:
            data = filebuf[cfg_offset : cfg_offset + cfg_length]
            if data[4:8] == b"\x00\x00\x00\x00":
                return
            with suppress(Exception):
                config = get_config(data)
                return config


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))

detection_rule = """
rule PikaBotLoader
{
    meta:
        author = "kevoreilly"
        description = "Pikabot Loader"
        cape_type = "PikaBot Loader"
    strings:
        $indirect = {31 C0 64 8B 0D C0 00 00 00 85 C9 74 01 40 50 8D 54 24 ?? E8 [4] A3 [4] 8B 25 [4] A1}
        $sysenter1 = {89 44 24 08 8D 85 ?? FC FF FF C7 44 24 04 FF FF 1F 00 89 04 24 E8}
        $sysenter2 = {C7 44 24 0C 00 00 00 02 C7 44 24 08 00 00 00 02 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PikaBot
{
    meta:
        author = "kevoreilly"
        description = "Pikabot Payload"
        cape_type = "PikaBot Payload"
        packed = "89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9"
    strings:
        $decode = {29 D1 01 4B ?? 8D 0C 10 89 4B ?? 85 F6 74 02 89 16}
        $indirect = {31 C0 64 8B 0D C0 00 00 00 85 C9 74 01 40 50 8D 54 24 ?? E8 [4] A3 [4] 8B 25 [4] A1}
        $config = {C7 44 24 [3] 00 00 C7 44 24 [4] 00 89 [1-4] ?? E8 [4] 31 C0 C7 44 24 [3] 00 00 89 44 24 ?? C7 04 24 [4] E8}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Pik23
{
    meta:
        author = "kevoreilly"
        description = "PikaBot Payload February 2023"
        cape_type = "PikaBot Payload"
        hash = "59f42ecde152f78731e54ea27e761bba748c9309a6ad1c2fd17f0e8b90f8aed1"
    strings:
        $rdtsc = {89 55 FC 89 45 F8 0F 31 89 55 F4 89 45 FC 33 C0 B8 05 00 00 00 C1 E8 02 2B C3 3B C1 0F 31 89 55 F0 89 45 F8 8B 44 8D}
        $int2d = {B8 00 00 00 00 CD 2D 90 C3 CC CC CC CC CC CC CC}
        $subsys = {64 A1 30 00 00 00 8B 40 18 C3}
        $rijndael = {EB 0F 0F B6 04 3? FE C? 8A 80 [4] 88 04 3? 0F B6 [3] 7C EA 5? 5? C9 C3}
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

"""
