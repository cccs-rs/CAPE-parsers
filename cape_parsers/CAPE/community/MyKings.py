"""
Description: MyKings AKA Smominru config parser
Author: x.com/YungBinary
"""

from contextlib import suppress
import json
import re
import base64


def contains_non_printable(byte_array):
    for byte in byte_array:
        if not chr(byte).isprintable():
            return True
    return False


def extract_base64_strings(data: bytes, minchars: int, maxchars: int) -> list:
    pattern = b"([A-Za-z0-9+/=]{" + str(minchars).encode() + b"," + str(maxchars).encode() + b"})\x00{4}"
    strings = []
    for string in re.findall(pattern, data):
        decoded_string = base64_and_printable(string.decode())
        if decoded_string:
            strings.append(decoded_string)
    return strings


def base64_and_printable(b64_string: str):
    with suppress(Exception):
        decoded_bytes = base64.b64decode(b64_string)
        if not contains_non_printable(decoded_bytes):
            return decoded_bytes.decode('ascii')


def extract_config(data: bytes) -> dict:
    config_dict = {}
    with suppress(Exception):
        cncs = extract_base64_strings(data, 12, 60)
        if cncs:
            # as they don't have schema they going under raw
            config_dict["raw"] = {"CNCs": cncs}
            return config_dict

    return {}


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))

detection_rule = """
rule MyKings 
{
    meta:
        author = "YungBinary"
        description = "https://x.com/YungBinary/status/1981108948498333900"
        cape_type = "MyKings Payload"
    strings: 
        $s1 = "login.php?uid=0" wide
        $s2 = "download.txt?rnd=" wide
        $s3 = "AcceptOK" ascii
        $s4 = "winsta0\\\\default" wide
        $s5 = "base64_ip.txt" wide
        $s6 = { 70 00 6F 00 77 00 65 00 72 00 74 00 6F 00 6F 00 6C 00 00 00 6B 00 61 00 73 00 70 00 65 00 72 00 73 00 6B 00 79 }
        $s7 = { 53 00 61 00 66 00 65 00 00 00 00 00 45 00 73 00 65 00 74 }
        $s8 = { 4E 00 6F 00 64 00 33 00 32 00 00 00 4D 00 61 00 6C 00 77 00 61 00 72 00 65 }
        $s9 = "Custom C++ HTTP Client/1.0" wide
        $s10 = "/ru \\"SYSTEM\\" /f" ascii
        $s11 = "cmd.exe /C timeout /t 1 & del " wide
        $s12 = "/login.aspx?uid=0" wide
        $s13 = "cmd-230812.ru" base64
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*))
}

"""
