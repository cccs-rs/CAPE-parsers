import struct
import pefile
import yara
import ipaddress
from contextlib import suppress


# V1 hash = 619751f5ed0a9716318092998f2e4561f27f7f429fe6103406ecf16e33837470
# V2 hash = 2f42dcf05dd87e6352491ff9d4ea3dc3f854df53d548a8da0c323be42df797b6 (32-bit payload)
# V2 hash = 8301936f439f43579cffe98e11e3224051e2fb890ffe9df680bbbd8db0729387 (64-bit payload)

RULE_SOURCE = """
rule StealC
{
    meta:
        author = "Yung Binary"
    strings:
        $decode_1 = {6A ?? 68 [4] 68 [4] E8}
        $decode_2 = {6A ?? 68 [4] 68 [4] [0-5] E8}
    condition:
        any of them
}
rule StealcV2
{
    meta:
        author = "kevoreilly"
    strings:
        $botnet32 = {AB AB AB AB 89 4B ?? C7 43 ?? 0F 00 00 00 88 0B A0 [4] EB 12 3C 20 74 0B 0F B6 06 8B CB 50 E8}
        $botnet64 = {0F 11 01 48 C7 41 ?? 00 00 00 00 48 8B D9 48 C7 41 ?? 0F 00 00 00 C6 01 00 8A 05 [4] EB ?? 3C 20 74 ?? 48 8B 4B ?? 44 8A 0F}
    condition:
        any of them
}
"""


def yara_scan(raw_data):
    yara_rules = yara.compile(source=RULE_SOURCE)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield block.identifier, instance.offset


def _is_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def xor_data(data, key):
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(data[i] ^ key[i])
    return decoded


def extract_ascii_string(data: bytes, offset: int, max_length=4096) -> str:
    if offset >= len(data):
        raise ValueError("Offset beyond data bounds")
    end = data.find(b'\x00', offset, offset + max_length)
    if end == -1:
        end = offset + max_length
    return data[offset:end].decode('ascii', errors='replace')


def parse_text(data):
    global domain, uri
    with suppress(Exception):
        lines = data.decode().split("\n")
        if not lines:
            return
        for line in lines:
            if line.startswith("http") and "://" in line:
                domain = line
            elif _is_ip(line):
                domain = line
            if line.startswith("/") and len(line) >= 4 and line[-4] == ".":
                uri = line


def parse_pe(data):
    global domain, uri, botnet_id
    pe = None
    image_base = 0
    last_str = ""
    with suppress(Exception):
        pe = pefile.PE(data=data, fast_load=True)
        if not pe:
            return
        image_base = pe.OPTIONAL_HEADER.ImageBase
        if not image_base:
            return
    for match in yara_scan(data):
        try:
            rule_str_name, str_decode_offset = match
            if rule_str_name.startswith("$botnet"):
                botnet_var = struct.unpack("I", data[str_decode_offset - 4 : str_decode_offset])[0]
                if hasattr(pe, 'OPTIONAL_HEADER'):
                    magic = pe.OPTIONAL_HEADER.Magic
                    if magic == 0x10b: # 32-bit
                        botnet_offset = pe.get_offset_from_rva(botnet_var - image_base)
                    elif magic == 0x20b: # 64-bit
                        botnet_offset = pe.get_offset_from_rva(pe.get_rva_from_offset(str_decode_offset) + botnet_var)
                    if botnet_offset:
                        botnet_id = extract_ascii_string(data, botnet_offset)
            str_size = int(data[str_decode_offset + 1])
            # Ignore size 0 strings
            if not str_size:
                continue
            if rule_str_name.startswith("$decode"):
                key_rva = data[str_decode_offset + 3 : str_decode_offset + 7]
                encoded_str_rva = data[str_decode_offset + 8 : str_decode_offset + 12]
                key_offset = pe.get_offset_from_rva(struct.unpack("i", key_rva)[0] - image_base)
                encoded_str_offset = pe.get_offset_from_rva(struct.unpack("i", encoded_str_rva)[0] - image_base)
                key = data[key_offset : key_offset + str_size]
                encoded_str = data[encoded_str_offset : encoded_str_offset + str_size]
                decoded_str = xor_data(encoded_str, key).decode()
                if last_str in ("http://", "https://"):
                    domain += decoded_str
                elif decoded_str in ("http://", "https://"):
                    domain = decoded_str
                elif "http" in decoded_str and "://" in decoded_str:
                    domain = decoded_str
                elif uri is None and decoded_str.startswith("/") and decoded_str[-4] == ".":
                    uri = decoded_str
                elif last_str[0] == "/" and last_str[-1] == "/":
                    botnet_id = decoded_str
                last_str = decoded_str
        except Exception:
            continue
    return


def extract_config(data):
    global domain, uri, botnet_id
    domain = uri = botnet_id = None
    config_dict = {}

    if data[:2] == b'MZ':
        parse_pe(data)
    else:
        parse_text(data)

    if domain and uri:
        config_dict.setdefault("CNCs", []).append(f"{domain}{uri}")

    if botnet_id:
        config_dict.setdefault("botnet", botnet_id)

    if "CNCs" not in config_dict:
        return {}
    
    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))

detection_rule = """
rule Stealc
{
    meta:
        author = "kevoreilly"
        description = "Stealc Payload"
        cape_type = "Stealc Payload"
        hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
    strings:
        $nugget1 = {68 04 01 00 00 6A 00 FF 15 [4] 50 FF 15}
        $nugget2 = {64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule StealcV2
{
    meta:
        author = "kevoreilly"
        description = "Stealc V2 Payload"
        cape_type = "Stealc Payload"
        packed = "2f42dcf05dd87e6352491ff9d4ea3dc3f854df53d548a8da0c323be42df797b6"
        packed = "8301936f439f43579cffe98e11e3224051e2fb890ffe9df680bbbd8db0729387"
    strings:
        $decode32 = {AB AB AB AB 8B 45 0C 89 4E 10 89 4E 14 39 45 08 75 0B C7 46 14 0F 00 00 00 88 0E EB 0F 2B 45 08 50 51 FF 75 ?? 8B}
        $dump32 = {33 C0 89 46 30 88 46 34 89 46 38 89 46 3C 89 46 40 89 46 44 89 46 48 89 46 4C 89 46 50 89 46 54 89 46 58 8B C6 5F 5E C3}
        $date32 = {F3 A5 8D 45 ?? 50 E8 [4] 59 8B F8 8B F2 8D 45 A4 50 E8 [4] 59 3B F2 7C 08 7F 04 3B F8 76 02 B3 01 8A C3}
        $decode64 = {40 53 48 83 EC 20 48 8B 19 48 85 DB 74 ?? 48 8B 53 18 48 83 FA 0F 76 2C 48 8B 0B 48 FF C2 48 81 FA 00 10 00 00 72}
        $dump64 = {48 8B C7 89 6F 40 40 88 6F 44 48 89 6F 48 48 89 6F 50 48 89 6F 58 48 89 6F 60 48 89 6F 68 48 89 6F 70 48 89 6F 78 48 89}
        $date64 = {0F 11 44 [2] 0F 11 8C [2] 00 00 00 89 8C [2] 00 00 00 48 8D 4C [2] E8 [4] 48 8B D8 48 8D 4C [2] E8 [4] 48 3B D8 0F 9F C0}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

"""
