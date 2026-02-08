import json
import struct
from contextlib import suppress
from typing import Any, Dict, Tuple

import pefile
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# Define the format for the fixed-size header part.
# <   : little-endian
# 32s : 32-byte string (for aes_key)
# 16s : 16-byte string (for iv)
# I   : 4-byte unsigned int (for dword1)
# I   : 4-byte unsigned int (for dword2)
HEADER_FORMAT = "<32s16sII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # This will be 32 + 16 + 4 + 4 = 56 bytes

def parse_blob(data: bytes):
    """
    Parse the blob according to the scheme:
      - 32 bytes = AES key
      - Next 16 bytes = IV
      - Next 2 DWORDs (8 bytes total) = XOR to get cipher data size
      - Remaining bytes = cipher data of that size
    """
    aes_key, iv, dword1, dword2 = struct.unpack_from(HEADER_FORMAT, data, 0)
    ciphertext_size = dword1 ^ dword2
    cipher_data = data[HEADER_SIZE : HEADER_SIZE + ciphertext_size]
    return aes_key, iv, cipher_data


def decrypt(data: bytes) -> Tuple[bytes, bytes, bytes]:
    aes_key, iv, cipher_data = parse_blob(data)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(cipher_data)
    return aes_key, iv, unpad(plaintext_padded, AES.block_size)


def extract_config(data: bytes) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    plaintext = b""
    data_section = None

    pe = pefile.PE(data=data, fast_load=True)
    for s in pe.sections:
        name = s.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        if name in ("UPX1", ".data"):
            data_section = s
            break

    if data_section is None:
        return cfg

    data = data_section.get_data()
    block_size = 4096
    zeros = b"\x00" * block_size
    offset = data.find(zeros)
    if offset == -1:
        return cfg

    while offset > 0:
        with suppress(Exception):
            aes_key, iv, plaintext = decrypt(data[offset : offset + block_size])
            if plaintext and b"conf" in plaintext:
                break

        offset -= 1

    if plaintext:
        try:
            parsed = json.loads(plaintext.decode("utf-8", errors="ignore").rstrip("\x00"))
        except json.JSONDecodeError:
            return cfg

        conf = parsed.get("conf", {})
        build = parsed.get("build", {})
        if conf:
            cfg = {
                "CNCs": conf.get("hosts"),
                "user_agent": conf.get("useragents"),
                "version": build.get("ver"),
                "build": build.get("build_id"),
                "cryptokey": aes_key.hex(),
                "cryptokey_type": "AES",
                "raw": {
                    "iv": iv.hex(),
                    "anti_vm": conf.get("anti_vm"),
                    "anti_dbg": conf.get("anti_dbg"),
                    "self_del": conf.get("self_del"),
                    "run_delay": conf.get("run_delay"),
                }
            }

    return cfg


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))

detection_rule = """
rule AuraStealer
{
    meta:
        author = "enzok"
        description = "AuraStealer Payload"
        cape_type = "AuraStealer Payload"
        unpacked = "a9c47f10d5eb77d7d6b356be00b4814a7c1e5bb75739b464beb6ea03fc36cc85"
        packed = "bac52ffc8072893ff26cdbf1df1ecbcbb1762ded80249d3c9d420f62ed0dc202"
    strings:
        $conf = {8D BE ?? 00 00 00 68 00 40 00 00 5? 5? FF D1 83 C4 ?? 8B 07 8B 57 04 29 C2}
        $key1 = {FF D2 8B 2B 8D 75 ?? 8B 5D ?? 33 5D ?? 8D 45}
        $key2 = {89 0B 89 F9 5? 5? 5? E8 [4] 8B 3F 8D 6F 38 8B 77 30 33 77 34 8D 47 20 8D 4C 24 ?? 89 FA 5? E8}
        $keyexpansion = {31 C0 8A 1C 82 88 1C 81 8A 5C 82 01 88 5C 81 01 8A 5C 82 02 88 5C 81 02 8A 5C 82 03 88 5C 81 03 4? 83 F8 08 75 ?? B? 08 00 00 00}
        $antivm2 = {8B 43 04 8B 0D [4] 3B 81 [4] B? [2] 00 00 B? [2] 00 00 0F 44 D1 85 C0 0F 44 D1 8B 8A [4] 03 8A [4] FF E1 31 FF EB ?? 8B 78 0C 33 78 10 B? [4] 03 05 [4] FF D0}
        $antivm1 = {39 04 11 0f 94 C3 8B 44 ?? ?? 85 C0}
    condition:
        3 of them
}

"""
