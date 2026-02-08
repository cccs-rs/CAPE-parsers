import socket
from contextlib import suppress


def _is_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except Exception:
        return False


def extract_config(data):
    config_dict = {}
    with suppress(Exception):
        if data[:2] == b"MZ":
            return
        for line in data.decode().split("\n"):
            if _is_ip(line) and line not in config_dict.get("CNCs", []):
                config_dict["CNCs"].append(line)
            elif line and "\\" in line:
                config_dict.setdefault("Timestamp path", []).append(line)
            elif "." in line and "=" not in line and line not in config_dict["CNCs"]:
                config_dict.setdefault("raw", {}).setdefault("Dummy domain", []).append(line)
        return config_dict

detection_rule = """
rule Socks5Systemz
{
    meta:
        author = "kevoreilly"
        description = "Socks5Systemz Payload"
        cape_type = "Socks5Systemz Payload"
        packed = "9b997d0de3fe83091726919a0dc653e22f8f8b20b1bb7d0b8485652e88396f29"
    strings:
        $chunk1 = {0F B6 84 8A [4] E9 [3] (00|FF)}
        $chunk2 = {0F B6 04 8D [4] E9 [3] (00|FF)}
        $chunk3 = {66 0F 6F 05 [4] E9 [3] (00|FF)}
        $chunk4 = {F0 0F B1 95 [4] E9 [3] (00|FF)}
        $chunk5 = {83 FA 04 E9 [3] (00|FF)}
        $chunk6 = {8A 04 8D [4] E9 [3] (00|FF)}
        $chunk7 = {83 C4 04 83 C4 04 E9}
        $chunk8 = {83 C2 04 87 14 24 5C E9}
    condition:
        uint16(0) == 0x5A4D and 5 of them
}

"""
