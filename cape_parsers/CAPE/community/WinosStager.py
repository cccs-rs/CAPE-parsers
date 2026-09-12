"""
Description: Winos 4.0 "OnlineModule" config parser
Author: x.com/YungBinary
"""

import re
from contextlib import suppress

CONFIG_KEY_MAP = {
    "dd": "execution_delay_seconds",
    "cl": "communication_interval_seconds",
    "bb": "version",
    "bz": "comment",
    "jp": "keylogger",
    "bh": "end_bluescreen",
    "ll": "anti_traffic_monitoring",
    "dl": "entrypoint",
    "sh": "process_daemon",
    "kl": "process_hollowing"
}


def find_config(data):
    start = ":db|".encode("utf-16le")
    end = ":1p|".encode("utf-16le")
    pattern = re.compile(re.escape(start) + b".*?" + re.escape(end), re.DOTALL)
    match = pattern.search(data)
    if match:
        return match.group(0).decode("utf-16le")


def extract_config(data: bytes) -> dict:
    config_dict = {}
    final_config = {}

    with suppress(Exception):
        config = find_config(data)
        if not config:
            return config_dict

        # Reverse the config string, which is delimited by '|'
        config = config[::-1]
        # Remove leading/trailing pipes and split into key/value pairs
        elements = [element for element in config.strip('|').split('|') if ':' in element]
        # Split each element for key : value in a dictionary
        config_dict = dict(element.split(':', 1) for element in elements)
        if config_dict:
            # Handle extraction and formatting of CNCs
            for i in range(1, 4):
                p, o, t = config_dict.get(f"p{i}"), config_dict.get(f"o{i}"), config_dict.get(f"t{i}")
                if p and p != "127.0.0.1" and o:
                    protocol = {"0": "udp", "1": "tcp"}.get(t)
                    if protocol:
                        cnc = f"{protocol}://{p}:{o}"
                        final_config.setdefault("CNCs", []).append(cnc)

            if "CNCs" not in final_config:
                return {}

            final_config["CNCs"] = list(set(final_config["CNCs"]))
            # Extract campaign ID
            final_config["campaign"] = "default" if config_dict["fz"] == "\u9ed8\u8ba4" else config_dict["fz"]

            # Check if the version has been extracted
            if "bb" in config_dict:
                final_config["version"] = config_dict["bb"]

            # Map keys, e.g. dd -> execution_delay_seconds
            final_config["raw"] = {v: config_dict[k] for k, v in CONFIG_KEY_MAP.items() if k in config_dict}

    return final_config


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))

detection_rule = """
rule WinosStager 
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/winos4-0-online-module-staging-component-used-in-cleversoar-campaign"
        cape_type = "WinosStager Payload"
    strings: 
        $s1 = "Windows\\\\SysWOW64\\\\tracerpt.exe" ascii fullword
        $s2 = "Windows\\\\System32\\\\tracerpt.exe" ascii fullword
        $s3 = { 70 00 31 00 3A 00 00 00 }
        $s4 = { 6F 00 31 00 3A 00 00 00 }
        $s5 = { 70 00 32 00 3A 00 00 00 }
        $s6 = { 6F 00 32 00 3A 00 00 00 }
        $s7 = { 70 00 33 00 3A 00 00 00 }
        $s8 = { 6F 00 33 00 3A 00 00 00 }
        $s9 = "IpDates_info" wide fullword
        $s10 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" wide fullword
        $s11 = "Console\\\\0" wide fullword
        $s12 = "d33f351a4aeea5e608853d1a56661059" wide fullword

        $config_parse = {
            (3B CE | 7D ??)                                  // cmp ecx, esi or jge short loc_??????
            (7D ?? | 0F 1F ?? 00)                            // jge short loc_?????? or nop dword ptr [??+00h]
            (66 83 3C 4D ?? ?? ?? ?? 7C | 66 41 83 ?? ?? 7C) // cmp ??, 7Ch ; '|'
            74 ??                                            // jz short loc_??????
            (41 | 48 FF C1)                                  // inc ecx or inc rcx
            (3B CE | FF C2)                                  // cmp ecx, esi or inc edx
            (7C ?? | 49 3B CB 7C ??)                         // jl loc_?????? | cmp rcx, r11, jl short loc_??????
        }
        $zero_config = {
            FF [1-5]                    // call
            83 (7C|7D) [1-2] 0A         // cmp [ebp+??], 0Ah
            0F 86 ?? ?? ?? ??           // jbe loc_??????
            (68 D0 07 00 00 | 33 D2)    // push 7D0h or xor edx,edx
            (6A 00 | 41 B8 D0 07 00 00) // push 0 or mov r8d, 0x7D0
            (68 ?? ?? ?? ?? | 48 8B CD) // push offset wszConfig or mov rcx, rbp
            E8                          // call
        }
    condition: 
        uint16(0) == 0x5a4d and ((3 of ($s*)) or ($config_parse or $zero_config))
}

"""
