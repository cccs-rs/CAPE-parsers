import logging
import struct
from contextlib import suppress

import pefile
from Cryptodome.Cipher import ARC4

log = logging.getLogger(__name__)

DESCRIPTION = "Adaptix beacon configuration parser."
AUTHOR = "enzok"


def parse_http_config(rc4_key: bytes, data: bytes) -> dict:
    config = {}
    offset = 0
    servers = []
    ports = []

    def read(fmt: str):
        nonlocal offset
        size = struct.calcsize(fmt)
        value = struct.unpack_from(fmt, data, offset)
        offset += size
        return value if len(value) > 1 else value[0]

    def read_str(length: int):
        nonlocal offset
        value = data[offset : offset + length].decode("utf-8", errors="replace")
        offset += length
        return value

    config["cryptokey"] = rc4_key.hex()
    config["cryptokey_type"] = "RC4"
    config["agent_type"] = f"{read('<I'):8X}"
    config["use_ssl"] = read("<B")
    host_count = read("<I")
    for host in range(host_count):
        host_length = read("<I")
        servers.append(read_str(host_length).strip("\x00"))
        ports.append(read("<I"))

    config["servers"] = servers
    config["ports"] = ports
    method_length = read("<I")
    config["http_method"] = read_str(method_length).strip("\x00")
    uri_length = read("<I")
    config["uri"] = read_str(uri_length).strip("\x00")
    parameter_length = read("<I")
    config["parameter"] = read_str(parameter_length).strip("\x00")
    useragent_length = read("<I")
    config["user_agent"] = read_str(useragent_length).strip("\x00")
    headers_length = read("<I")
    config["http_headers"] = read_str(headers_length).strip("\x00")
    config["ans_pre_size"] = read("<I")
    config["ans_size"] = read("<I")
    config["kill_date"] = read("<I")
    config["working_time"] = read("<I")
    config["sleep_delay"] = read("<I")
    config["jitter_delay"] = read("<I")

    output = {"raw": config}

    # Map some fields to CAPE's output format, where possible
    output['cryptokey'] = config['cryptokey']
    output['cryptokey_type'] = config['cryptokey_type']
    output['user_agent'] = config['user_agent']
    output['CNCs'] = [f"{'https' if config['use_ssl'] else 'http'}://{server}:{ports[i]}{config['uri']}"
                      for i, server in enumerate(servers)]

    # TODO: Does agent_type map to version or build?
    # output['version'] = output['raw']['agent_type']

    return output


def extract_config(filebuf: bytes) -> dict:
    pe = pefile.PE(data=filebuf, fast_load=True)
    data_sections = [s for s in pe.sections if b".rdata" in s.Name]
    if not data_sections:
        return

    data = data_sections[0].get_data()
    data_len = len(data)
    pos = 0
    while pos + 4 <= data_len:
        start_offset = pos
        key_offset = struct.unpack_from("<I", data, pos)[0]
        pos += 4

        if pos + key_offset + 32 > data_len:
            pos = start_offset + 1
            continue

        encrypted_data = data[pos : pos + key_offset]
        pos += key_offset
        rc4_key = data[pos : pos + 16]

        if key_offset == 787:
            pass

        with suppress(Exception):
            decrypted = ARC4.new(rc4_key).decrypt(encrypted_data)
            if b"User-Agent" in decrypted:
                return parse_http_config(rc4_key, decrypted)

        pos = start_offset + 1

    return None


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))

detection_rule = """
rule AdaptixBeacon
{
    meta:
        author = "enzok"
        description = "AdaptixBeacon Payload"
        cape_type = "AdaptixBeacon Payload"
        hash = "f78f5803be5704420cbb2e0ac3c57fcb3d9cdf443fbf1233c069760bee115b5d"
    strings:
        $conf_1 = {8D ?? ?? E8 [3] 00 4? 89 [1-2] 4? 8B 4C 24 ?? E8 [3] 00 4? 8B 53 48 66 [0-1] 89 04 ?? E8}
        $conf_2 = {E8 [3] 00 48 8B 4C 24 ?? 48 89 43 78 E8 [3] 00 48 8B 4C 24 ?? 89 83 80 00 00 00 E8 [3] 00 03 83 80 00 00 00 48 8B 4C 24}
        $conf_3 = {E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 58 E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 60 E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 68}
        $conf_4 = {8D ?? ?? 4? 89 ?? FF ?? 4? 89 ?? 4? 89 ?? 4? 8B ?? FF ?? ?? 4? 8B ?? 48 66 ?? 89 ?? ?? EB}
        $conf_5 = {48 89 ?? 4? 89 ?? FF ?? 4? 89 ?? 4? 89 D9 4? 89 ?? ?? 4? 8B 03 FF ?? ?? 4? 89 ?? 4? 89 ?? 4? 89 ?? ?? 4? 8B 03 FF ?? ?? 4? 89}
        $wininet_1 = {B9 77 00 00 00 [0-4] E8 [4] B9 69 00 00 00 88 ?4 24 [0-4] E8 [4] B9 6E 00 00 00 88 ?4 24}
        $wininet_2 = {B9 69 00 00 00 88 ?4 24 [0-4] E8 [4] B9 6E 00 00 00 88 ?4 24 [0-4] E8 [4] B9 65 00 00 00 88 ?4 24}
    condition:
        1 of ($conf_*) and 1 of ($wininet_*)
}

"""
