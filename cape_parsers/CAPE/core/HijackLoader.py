from contextlib import suppress

try:
    from cape_parsers.utils.strings import extract_strings
except ImportError as e:
    print(f"Problem importing extract_strings: {e}")

import logging
log = logging.getLogger(__name__)


def extract_config(data: bytes):
    config = {}

    with suppress(Exception):
        if data[:2] == b"MZ":
            return

        header_data = data[:1024]
        lines = extract_strings(data=header_data, minchars=3, dedup=False)

        if len(lines) < 4:
            return None

        if '\\' in lines[2]:
            config.setdefault("raw", {})["directory"] = (lines[1].strip() + '\\' + lines[0].strip()).replace('  ', ' ')
            config.setdefault("raw", {})["inject_dll"] = lines[2].strip()
        if '.exe' in lines[3]:
            config.setdefault("raw", {})["exe_name"] = lines[3].strip()

        if config:
            config.setdefault("raw", config)
            return config

if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))

detection_rule = """
rule HijackLoaderStub
{
    meta:
        author = "kevoreilly"
        description = "HijackLoader Stub Executable"
        cape_type = "HijackLoader Payload"
    strings:
        $stub1 = {50 83 C0 10 50 56 8D 85 [4] 50 E8 [4] 83 C7 30 8D 85 [4] 3B F8 74 08 8B 35 [4] EB D3}
        $stub2 = {33 C5 89 45 ?? (C6 45 ?? 00|C7 45 ?? 61 7A 2D 2D) 8D 45 ?? FF 75 ?? C7 45 ?? 30 39 41 5A 50 8D 45 (??|?? C7 45 ?? 61 7A 2D 2D) 50 E8}
        $app = "\\\\app-" wide
    condition:
        2 of them
}

"""
